import json
import csv
import getpass
import logging
from netmiko import ConnectHandler
import ipaddress
import re
from tabulate import tabulate
from datetime import datetime
from prettytable import PrettyTable

# Настраиваем логирование
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('route_inspector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def get_vlan_descriptions(desc_output):
    vlan_descriptions = {}
    lines = desc_output.splitlines()
    for line in lines:
        match = re.match(r"^(\S+)\s+\S+\s+\S+\s+(.*)$", line)
        if match:
            iface = match.group(1)
            desc = match.group(2).strip()
            desc = re.sub(r"[-=]*\s*", "", desc)
            sub_match = re.search(r'\.(\d+)$', iface)
            svi_match = re.search(r'(?:Vl(an)?)(\d+)', iface)
            vlan_id = None
            if sub_match:
                vlan_id = int(sub_match.group(1))
            elif svi_match:
                vlan_id = int(svi_match.group(2))
            if vlan_id is not None:
                vlan_descriptions[vlan_id] = desc
    return vlan_descriptions


def get_vlan_info_from_brief(vlan_brief_output):
    vlan_info = {}
    lines = vlan_brief_output.splitlines()
    in_table = False
    for line in lines:
        if re.match(r"^VLAN\s+Name", line):
            in_table = True
            continue
        if in_table and re.match(r"^\d+", line):
            match = re.match(
                r'^(\d{1,4})\s+(.+?)\s+(active|suspended|act/unsup|act/lshut|sus/lshut|suspended)(?:\s+|$)',
                line.strip())
            if match:
                vlan_id = int(match.group(1))
                name = match.group(2).strip()
                status = match.group(3)
                if (vlan_id < 1002 or vlan_id > 1005) and 'unsup' not in status:
                    vlan_info[vlan_id] = name
    return vlan_info


def calculate_subnet_info(prefix, mask):
    network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    wildcard_mask = ipaddress.IPv4Address(int(network.hostmask))
    first = str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address)
    last = str(list(network.hosts())[-1]) if network.num_addresses > 2 else str(network.broadcast_address)
    return {
        "mask": str(network.netmask),
        "wildcard": str(wildcard_mask),
        "range": f"{first} - {last}",
        "hosts": network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses
    }


def get_svi_info(net_connect, vlan_id):
    cmd = f"show ip interface vlan {vlan_id}"
    output = net_connect.send_command(cmd)
    ip_match = re.search(r"Internet address is (\d+\.\d+\.\d+\.\d+)/(\d+)", output)
    if ip_match:
        prefix, mask = ip_match.groups()
        return prefix, mask
    return None, None


def get_default_gateway(net_connect):
    cmd = "show ip default-gateway"
    output = net_connect.send_command(cmd).strip()
    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
    if match:
        return match.group(1)
    return "Не настроен"


def process_device(device_config, creds):
    device = {
        "device_type": creds["device_type"],
        "host": device_config["host"],
        "username": creds["username"],
        "password": creds["password"],
        "secret": creds["secret"],
        "port": device_config["port"],
        "timeout": 30,
        "global_delay_factor": 2
    }

    try:
        logger.info(f"Подключение к {device['host']}")
        net_connect = ConnectHandler(**device)
        logger.info("Подключение установлено")
        net_connect.enable()
        logger.info("Режим enable активирован")

        # Получаем hostname из промпта
        prompt = net_connect.find_prompt()
        hostname = prompt.rstrip('#').strip()  # Удаляем # и пробелы
        logger.info(f"Hostname: {hostname}")

        show_desc_cmd = "show interfaces description"
        logger.info(f"Отправка команды: {show_desc_cmd}")
        desc_output = net_connect.send_command(show_desc_cmd)
        logger.info(f"Получен вывод команды: {show_desc_cmd}")

        show_route_cmd = "show ip route"
        logger.info(f"Отправка команды: {show_route_cmd}")
        routes_output = net_connect.send_command(show_route_cmd)
        logger.info(f"Получен вывод команды: {show_route_cmd}")

        vlan_descriptions = get_vlan_descriptions(desc_output)

        device_type = device_config.get("type", "unknown")
        table = []
        added_vlans = set()

        # Парсинг маршрутов (для L3 и роутеров)
        route_lines = routes_output.splitlines()
        for line in route_lines:
            line = line.strip()
            # Подключенные сети (C)
            match_c = re.match(r"^C\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+is directly connected,\s+(\S+)", line)
            if match_c:
                prefix, mask, iface = match_c.groups()
                vlan_id = None
                match_vl = re.match(r"(?:Vlan|Vl)(\d+)", iface)
                if match_vl:
                    vlan_id = int(match_vl.group(1))
                else:
                    match_sub = re.match(r".*\.(\d+)", iface)
                    if match_sub:
                        vlan_id = int(match_sub.group(1))
                subnet = calculate_subnet_info(prefix, mask)
                if vlan_id is not None:
                    added_vlans.add(vlan_id)
                    desc = vlan_descriptions.get(vlan_id, "")
                    table.append([device_type, hostname, vlan_id, desc, prefix, subnet["mask"], subnet["wildcard"],
                                  subnet["range"], subnet["hosts"], subnet["range"].split(" - ")[0]])
                else:
                    table.append(
                        [device_type, hostname, iface, "Физический интерфейс или другой", prefix, subnet["mask"],
                         subnet["wildcard"], subnet["range"], subnet["hosts"], prefix])
                continue
            # Локальные интерфейсы (L), только non-VLAN
            match_local = re.match(r"^L\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+is directly connected,\s+(\S+)", line)
            if match_local:
                prefix, mask, iface = match_local.groups()
                vlan_id = None
                match_vl = re.match(r"(?:Vlan|Vl)(\d+)", iface)
                if match_vl:
                    vlan_id = int(match_vl.group(1))
                else:
                    match_sub = re.match(r".*\.(\d+)", iface)
                    if match_sub:
                        vlan_id = int(match_sub.group(1))
                if vlan_id is None:
                    subnet = calculate_subnet_info(prefix, mask)
                    table.append(
                        [device_type, hostname, iface, "Loopback или физический интерфейс", prefix, subnet["mask"],
                         subnet["wildcard"], subnet["range"], subnet["hosts"], prefix])
                continue
            # Внешние маршруты
            match_ext = re.search(
                r"\b(S|O|B|D|EX|E1|E2|IA)\s+(\d+\.\d+\.\d+\.\d+)/(\d+)[^\n]*?via\s+(\d+\.\d+\.\d+\.\d+)", line)
            if match_ext:
                route_type, prefix, mask, nexthop = match_ext.groups()
                subnet = calculate_subnet_info(prefix, mask)
                table.append(
                    [device_type, hostname, "ext", "внешние маршруты", prefix, subnet["mask"], subnet["wildcard"],
                     subnet["range"], subnet["hosts"], nexthop])
                continue

        # Получение VLAN из show vlan brief (для свитчей L2/L3)
        show_vlan_cmd = "show vlan brief"
        logger.info(f"Отправка команды: {show_vlan_cmd}")
        vlan_brief_output = net_connect.send_command(show_vlan_cmd)
        logger.info(f"Получен вывод команды: {show_vlan_cmd}")

        vlan_info_from_brief = {}
        if "Invalid input" not in vlan_brief_output and vlan_brief_output.strip():
            vlan_info_from_brief = get_vlan_info_from_brief(vlan_brief_output)

        default_gateway = get_default_gateway(net_connect)
        logger.info(f"Default gateway: {default_gateway}")

        # Объединяем имена VLAN (будем приоритезировать позже)
        vlan_names = {**vlan_info_from_brief, **vlan_descriptions}

        # Добавляем VLAN, не покрытые маршрутами (для L2 или L3 без IP)
        for vlan_id, desc in sorted(vlan_names.items()):
            if vlan_id in added_vlans:
                continue
            prefix, mask = get_svi_info(net_connect, vlan_id)
            if prefix and mask:
                subnet = calculate_subnet_info(prefix, mask)
                gateway = default_gateway if default_gateway != "Не настроен" else subnet["range"].split(" - ")[0]
                table.append(
                    [device_type, hostname, vlan_id, desc, prefix, subnet["mask"], subnet["wildcard"], subnet["range"],
                     subnet["hosts"], gateway])
            else:
                table.append(
                    [device_type, hostname, vlan_id, desc, "Нет IP", "N/A", "N/A", "N/A", "N/A", default_gateway])

        net_connect.disconnect()
        logger.info("Подключение закрыто")
        return table, hostname

    except Exception as e:
        logger.error(f"Ошибка на устройстве {device['host']}: {e}", exc_info=True)
        return [], device["host"]


def prioritize_vlan_names(all_tables):
    vlan_name_priority = {}
    for table in all_tables:
        device_type = table[0][0] if table else "unknown"
        for row in table:
            vlan_id = row[2]
            name = row[3]
            if vlan_id != "ext" and name and name not in ["Физический интерфейс или другой",
                                                          "Loopback или физический интерфейс"]:
                priority = 0
                if device_type == "core":
                    priority = 3
                elif device_type == "access":
                    priority = 2
                elif device_type == "router":
                    priority = 1
                if vlan_id not in vlan_name_priority or priority > vlan_name_priority[vlan_id][1]:
                    vlan_name_priority[vlan_id] = (name, priority)

    # Обновляем имена в таблицах
    combined_table = []
    for table in all_tables:
        for row in table:
            vlan_id = row[2]
            if vlan_id != "ext" and vlan_id in vlan_name_priority:
                row[3] = vlan_name_priority[vlan_id][0]
            combined_table.append(row)
    return combined_table


def main():
    try:
        logger.info("Запуск скрипта RouteInspector")

        # Загружаем конфигурацию
        logger.info("Чтение switch_config.json")
        with open("config/switch_config.json", encoding='utf-8') as f:
            config = json.load(f)
        logger.info(f"Конфигурация загружена: {config}")

        # Загружаем учетные данные
        logger.info("Чтение credentials.json")
        with open("config/credentials.json", encoding='utf-8') as f:
            creds = json.load(f)
        logger.info(f"Учетные данные загружены: {creds}")

        # Запрашиваем пароль и secret
        logger.info(f"Запрос пароля для пользователя {creds['username']}")
        creds['password'] = getpass.getpass(f"Введите пароль для пользователя {creds['username']}: ")
        logger.info("Пароль успешно введен")
        logger.info(f"Запрос enable secret для пользователя {creds['username']}")
        creds['secret'] = getpass.getpass(f"Введите enable secret для пользователя {creds['username']}: ")
        logger.info("Enable secret успешно введен")

        # Обрабатываем устройства
        all_tables = []
        hostnames = []
        devices = []

        # Собираем устройства из конфига
        if "router" in config:
            devices.append(
                {"type": "router", "host": config["router"]["host"], "port": config["router"].get("port", 22)})
        if "core" in config:
            devices.append({"type": "core", "host": config["core"]["host"], "port": config["core"].get("port", 22)})
        for key, device_config in config.items():
            if key.startswith("access_sw"):
                devices.append({"type": "access", "host": device_config["host"], "port": device_config.get("port", 22)})

        for device_config in devices:
            table, hostname = process_device(device_config, creds)
            all_tables.append(table)

            if device_config["type"] == "router":
                router_hostname = hostname

        # Приоритезация имен VLAN
        combined_table = prioritize_vlan_names(all_tables)

        # Вывод таблицы
        headers = ["Тип устройства", "Hostname", "VLAN", "VLAN Name", "Сеть", "Маска", "Обратная маска", "Диапазон IP",
                   "Кол-во хостов", "Шлюз"]
        logger.info("Вывод таблицы маршрутов (tabulate)")
        print("\n📋 Таблица маршрутов:")
        print(tabulate(combined_table, headers=headers, tablefmt="grid"))

        logger.info("Вывод таблицы маршрутов (PrettyTable)")
        pretty_table = PrettyTable()
        pretty_table.field_names = headers
        for row in combined_table:
            pretty_table.add_row(row)
        print("\n📋 Таблица маршрутов:")
        print(pretty_table)

        # Сохранение в CSV
        date_time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{router_hostname}_{date_time_str}.csv"

        logger.info(f"Сохранение в CSV: {filename}")
        with open(filename, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(headers)
            writer.writerows(combined_table)

        print(f"\n💾 Данные сохранены в файл: {filename}")

    except FileNotFoundError as e:
        logger.error(f"Ошибка: Файл не найден - {e}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка: Неверный формат JSON - {e}")
        raise
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()