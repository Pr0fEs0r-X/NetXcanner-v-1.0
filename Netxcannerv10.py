import argparse
import socket
import sys
from scapy.all import ARP, Ether, srp

def get_local_network_range():
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    
    
    parts = local_ip.split('.')
    network_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    return local_ip, network_range

def get_hostname(ip):
    """
    Intenta resolver el nombre de host para una IP dada.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Desconocido"
    except Exception:
        return "N/A"

def scan_network(network_range):
    """
    Realiza el escaneo ARP utilizando Scapy.
    """
    print(f"\n[*] Escaneando la red: {network_range} ...\n")
    print("-" * 75)
    print(f"{'IP':<18} {'MAC Address':<20} {'Hostname'}")
    print("-" * 75)

    
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    try:
       
        result = srp(packet, timeout=3, verbose=0)[0]
    except PermissionError:
        print("\n[!] Error de permisos. Por favor, ejecuta el script como Administrador (Windows) o con sudo (Linux).")
        sys.exit(1)
    except OSError as e:
        print(f"\n[!] Error de Sistema: {e}")
        print("[!] Asegúrate de tener Npcap instalado si estás en Windows.")
        sys.exit(1)

    devices = []

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)
        devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})

    if not devices:
        print("[!] No se encontraron dispositivos activos.")
    else:
        for device in devices:
            print(f"{device['ip']:<18} {device['mac']:<20} {device['hostname']}")
    
    print("-" * 75)
    print(f"[*] Total de dispositivos encontrados: {len(devices)}\n")

def main():
    
    parser = argparse.ArgumentParser(
        description="Escáner de Red Local (ARP Scanner). Detecta dispositivos activos, sus direcciones MAC y nombres de host.",
        epilog="Ejemplos de uso:\n"
               "  python network_scanner.py\n"
               "  python network_scanner.py -t 192.168.0.1/24\n"
               "  sudo python3 network_scanner.py -t 10.0.0.0/24",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    
    parser.add_argument(
        "-t", "--target", 
        metavar="RANGO", 
        help="Especifica el rango de red a escanear en formato CIDR (ej: 192.168.1.0/24). Si no se especifica, se detecta automáticamente."
    )

    
    args = parser.parse_args()

    
    if args.target:
        
        target_network = args.target
        print(f"[*] Usando rango especificado manualmente: {target_network}")
    else:
        
        my_ip, target_network = get_local_network_range()
        print(f"[*] Tu IP local parece ser: {my_ip}")
    
   
    scan_network(target_network)

if __name__ == "__main__":
    main()