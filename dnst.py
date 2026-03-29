import socket
import struct
import time
import sys
from concurrent.futures import ThreadPoolExecutor

dns_servers = {
    "8.8.8.8": "Google Primary",
    "8.8.4.4": "Google Secondary",
    "1.1.1.1": "Cloudflare Primary",
    "1.0.0.1": "Cloudflare Secondary",
    "1.1.1.2": "Cloudflare Malware Primary",
    "1.0.0.2": "Cloudflare Malware Secondary",
    "1.1.1.3": "Cloudflare Family Primary",
    "1.0.0.3": "Cloudflare Family Secondary",
    "9.9.9.9": "Quad9 Primary",
    "149.112.112.112": "Quad9 Secondary",
    "9.9.9.11": "Quad9 Esc Primary",
    "149.112.112.11": "Quad9 Esc secondary",
    "9.9.9.10": "Quad9 Unsecured Primary",
    "149.112.112.10": "Quad9 Unsecured Secondary",
    "77.88.8.8": "Yandex Basic Primary",
    "77.88.8.1": "Yandex Basic Secondary",
    "77.88.8.88": "Yandex Safe Primary",
    "77.88.8.2": "Yandex Safe Secondary",
    "77.88.8.7": "Yandex Family Primary",
    "77.88.8.3": "Yandex Family Secondary",
    "208.67.222.222": "OpenDNS Primary",
    "208.67.220.220": "OpenDNS Secondary",
    "94.140.14.14": "AdGuard DNS Primary",
    "94.140.15.15": "AdGuard DNS Secondary",
    "94.140.14.140": "AdGuard Non-filtering Primary",
    "94.140.14.141": "AdGuard Non-filtering Secondary",
    "94.140.14.15": "AdGuard Family Primary",
    "94.140.15.16": "AdGuard Family Secondary",
    # Some local DNS servers to check whether ISP is tampering with DNS responses
    "84.17.229.102": "MTS Bryansk",
    "62.231.4.153": "Vimpelcom Khimki",
    "37.110.31.139": "Rostelecom Moscow",
    "87.117.39.15": "Rostelecom Rostov-na-Donu",
    "83.150.6.68": "Switzerland Iway AG",
    "193.135.215.30": "Swisscom",
    "91.65.153.97": "Vodafone Berlin",
    "87.128.56.98": "Deutsche Telekom Berlin",
    "93.241.8.154": "Deutsche Telekom Dortmund",
    "51.15.193.202": "SCALEWAY Paris",
    "89.40.220.114": "Eurofiber France Paris",
    "80.124.25.102": "Societe Francaise Du Lyon",
    "89.234.182.131": "Netrix Marseille",
    "194.75.199.115": "British Telecom Bridlington",
    "185.239.206.73": "Pangea Connected Limited Bristol",
    "81.130.177.57": "British Telecom London",
    "82.165.204.89": "IONOS London",
    "62.92.255.150": "Telenor Norge Oslo",
    "185.247.99.87": "mnemonic  Oslo",
}


def get_dns(domain, dns_server, name, timeout=0.5):
    header = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    qname = (
        b"".join(struct.pack("!B", len(p)) + p.encode() for p in domain.split(".")) + b"\x00"
    )
    query = header + qname + struct.pack("!HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    data = None
    try:
        start_time = time.perf_counter()

        sock.sendto(query, (dns_server, 53))
        data, addr = sock.recvfrom(512)

        end_time = time.perf_counter()

        latency = round((end_time - start_time) * 1000, 2)

        if not data:
            return None

        answ_num = struct.unpack("!H", data[6:8])[0]

        if answ_num > 0:
            ip_bytes = data[-4:]
            ip = ".".join(map(str, ip_bytes))
            return {"name": name, "server": dns_server, "ip": ip, "ms": latency}

    except Exception as e:
        print(f"Error {name} {dns_server}: {e}")
    finally:
        sock.close()

    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python dns_test.py <domain>")
        return

    domain = sys.argv[1]
    result = []

    with ThreadPoolExecutor(max_workers=len(dns_servers)) as executor:
        futures = [executor.submit(get_dns, domain, dns, name) for dns, name in dns_servers.items()]
        for f in futures:
            res = f.result()
            if res:
                result.append(res)
    result.sort(key=lambda x: x["ms"])

    print(f"\n{'ISP':<32} | {'DNS SERVER':<16} | {'RESOLVED IP':<16} | {'PING'}")
    print("-" * 80)
    for res in result:
        print(
            f"{res['name']:<32} | {res['server']:<16} | {res['ip']:<16} | {res['ms']:.2f} ms"
        )


if __name__ == "__main__":
    main()
