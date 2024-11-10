import scapy.all as scapy
import re
import logging
import requests
import socket

def capture_traffic():
    logging.basicConfig(filename="py_log.log", level=logging.INFO)
    print("Введите фильтры для захвата трафика:")
    protocol_filter = input("Протоколы:")
    ip_filter = input("IP-адреса:")
    port_filter = input("Порты:")
    packet_limit = input("Количество пакетов для захвата:")

    filter_value = f"{protocol_filter} {ip_filter} {port_filter}"
    if packet_limit.lower() == "n":
        packets = scapy.sniff(filter=filter_value)
    else:
        packets = scapy.sniff(filter=filter_value, count=int(packet_limit))
    
    scapy.wrpcap('network_capture.pcap', packets)
    print("Захват трафика завершен и сохранен в 'network_capture.pcap'.")


def route_trace(destination_ip):
    ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\da-f]{0,4}\:*[\da-f]{0,4}\:*[\da-f]{0,4}\:*[\da-f]{0,4}\:[\da-f]{0,4}\:*[\da-f]{0,4}\:*[\da-f]{0,4}\:*[\da-f]{0,4}"
    trace_results = []

    for ttl_value in range(1, 30):
        response = scapy.sr1(scapy.IP(dst=destination_ip, ttl=ttl_value)/scapy.UDP(dport=33434), verbose=0, timeout=5)
        if response is None:
            print("Нет ответа от узла.")
            continue
        elif response.src == destination_ip:
            trace_results.append(response.src)
            print("Достигнут целевой узел:", response.src)
            break
        else:
            detected_ip = re.findall(ip_regex, response[0].summary())[0].strip()
            trace_results.append(detected_ip)
            print("Промежуточный узел:", detected_ip)

    print("Маршрут:", trace_results)
    return trace_results





def dns_to_ip(domain_name):
    ip_reg = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    dns_response = scapy.sr1(scapy.IP(dst="77.88.44.55")/scapy.UDP(dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain_name)), verbose=0)
    resolved_ip = re.findall(ip_reg, dns_response[scapy.DNS].summary())[0].strip()
    print(f"IP-адрес для домена {domain_name}: {resolved_ip}")
    return resolved_ip


def scanner_port(target_ip):
    print(f"Сканирование портов для IP: {target_ip}")
    ports_result = f"IP: {target_ip}\nПорт     Статус\n"
    for port in range(1, 201):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            connection_result = sock.connect((target_ip, port))
            if connection_result == 0:
                place = " " * (5 - len(str(port)))
                ports_result += f"{port}{place}     Открыт\n"
    print(ports_result)


def organization_info(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?lang=ru")
        org_data = response.json()
        
        if org_data["status"] == "success":
            print(f"\nIP: {ip_address}")
            print(f"Страна: {org_data['country']}")
            print(f"Организация: {org_data['org']}")
        else:
            print("Не удалось определить организацию для данного IP-адреса.")
    except requests.RequestException as e:
        print("Ошибка при получении данных:", e)



def network_analysis(ip_or_domain):
    if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip_or_domain):
        ip_or_domain = dns_to_ip(ip_or_domain)

    route_list = route_trace(ip_or_domain)
    print("\nМаршрут определен. Начинается проверка узлов...\n")

    for node_ip in route_list:
        print(f"\nУзел: {node_ip}")
        organization_info(node_ip)
        scanner_port(node_ip)
network_analysis("")
