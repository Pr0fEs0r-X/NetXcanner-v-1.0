#puedes copiarlo y usarlo lo que gustes
#ahi se los dejo este 2026 v 1.0 ,)
import subprocess
import platform
import re
import socket
import ipaddress
import urllib.request
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pyfiglet

# --- aqui configuro los colores de la consola :) ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ACCENT = '\033[94m'
    SUCCESS = '\033[92m'
    INFO = '\033[93m'
    ERROR = '\033[91m'
    RESET = '\033[0m'

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    # Genero aqui el TITULO ASCII Art con pyfiglet fuente doom
    try:
        ascii_art = pyfiglet.figlet_format("NetXcanner v 1.1", font="doom")
        print(f"{Colors.ACCENT}{ascii_art}{Colors.RESET}")
    except:
        print(f"{Colors.ACCENT}NetXcanner v 1.1{Colors.RESET}")
    
    print(f"{Colors.INFO}                      by Pr@fEsOr X{Colors.RESET}")
    
    
    try:
        rhino_art = pyfiglet.figlet_format("Rhino Toolkit v 1.0", font="bubble")
        print(f"{Colors.FAIL}{rhino_art}{Colors.RESET}")
    except:
        print(f"{Colors.FAIL}Rhino Toolkit v 1.0{Colors.RESET}")
    
    print("\n")

def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except:
        return "192.168.1.0/24"

def ping_and_get_ttl(ip):
    command = ['ping', '-n', '1', '-w', '300', str(ip)]
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL, startupinfo=startupinfo)
        output_text = output.decode('utf-8', errors='ignore')
        match = re.search(r"TTL=(\d+)", output_text, re.IGNORECASE)
        if match:
            return True, int(match.group(1))
        return True, None
    except:
        return False, None

def get_mac_from_arp(ip):
    try:
        command = ['arp', '-a', str(ip)]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL, startupinfo=startupinfo)
        output = output.decode('utf-8', errors='ignore')
        match = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
        if match: 
            return match.group(1).replace('-', ':').upper()
    except:
        pass
    return None

def get_vendor(mac):
    if not mac: return "Desconocido"
    try:
        clean_mac = mac.replace(":", "")
        oui = clean_mac[:6]
        url = f"https://api.macvendors.com/{oui}"
        req = urllib.request.Request(url, headers={'User-Agent': 'NetXcanner/1.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode('utf-8')
    except:
        return "Desconocido"

def get_hostname(ip):
    try: 
        return socket.gethostbyaddr(str(ip))[0]
    except: 
        return "N/A"

def guess_os(ttl, vendor):
    if ttl is None: return "Desconocido"
    vendor_low = vendor.lower()
    if ttl <= 64:
        if "apple" in vendor_low: return "iOS/macOS"
        elif any(x in vendor_low for x in ["samsung", "xiaomi", "huawei", "lg", "motorola"]): return "Android"
        else: return "Linux/Unix"
    elif ttl <= 128: return "Windows"
    elif ttl > 128 and ttl <= 255: return "Router/Switch"
    return "Desconocido"

def scan_ports(ip):
    common_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389, 8080]
    open_ports = []
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((str(ip), port))
            if result == 0: open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def scan_device(ip):
    is_alive, ttl = ping_and_get_ttl(ip)
    if is_alive:
        mac = get_mac_from_arp(ip)
        vendor = "Desconocido"
        if mac: vendor = get_vendor(mac)
        else: mac = "No Resuelta"
        
        os_name = guess_os(ttl, vendor)
        hostname = get_hostname(ip)
        ports = scan_ports(ip)
        
        return {
            'ip': str(ip), 'mac': mac, 'vendor': vendor,
            'os': os_name, 'hostname': hostname,
            'status': "Activo", 'ports': ports
        }
    return None

def run_tool(command, ip):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                   text=True, encoding='cp850', errors='replace')
        for line in process.stdout:
            print(f"  {line}", end='')
    except Exception as e:
        print(f"{Colors.ERROR}Error: {str(e)}{Colors.RESET}")

def grab_banner(ip, ports):
    if not ports:
        print(f"{Colors.WARNING}No hay puertos abiertos para analizar.{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}[*] Detectando Versiones de Servicios en {ip}...{Colors.RESET}")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            if port in [80, 8080, 443]:
                s.send(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                print(f"  {Colors.SUCCESS}Puerto {port}:{Colors.RESET} {banner.split(chr(10))[0]}")
            else:
                print(f"  {Colors.WARNING}Puerto {port}:{Colors.RESET} Sin respuesta")
            s.close()
        except Exception as e:
            print(f"  {Colors.ERROR}Puerto {port}:{Colors.RESET} Error al conectar.")

def show_device_menu(device):
    ip = device['ip']
    while True:
        print(f"\n{Colors.ACCENT}{'='*50}{Colors.RESET}")
        print(f"{Colors.BOLD} HERRAMIENTAS PARA: {ip}{Colors.RESET}")
        print(f"{Colors.ACCENT}{'='*50}{Colors.RESET}")
        print(f" MAC:        {device['mac']}")
        print(f" Fabricante: {device['vendor']}")
        print(f" S.O.:       {device['os']}")
        print(f" Hostname:   {device['hostname']}")
        print(f" Puertos:    {', '.join(map(str, device['ports'])) if device['ports'] else 'Ninguno'}")
        print(f" {Colors.ACCENT}{'='*50}{Colors.RESET}")
        
        print(f"\n  1. Ping")
        print(f"  2. NsLookup")
        print(f"  3. Tracert")
        print(f"  4. PathPing")
        print(f"  5. Svc Version (Detectar Versiones)")
        print(f"  6. Volver al menú principal")
        
        choice = input(f"\n {Colors.BOLD}Selecciona una opción > {Colors.RESET}")
        
        if choice == '1':
            cmd = ['ping', '-n', '4', ip] if platform.system() == 'Windows' else ['ping', '-c', '4', ip]
            run_tool(cmd, ip)
        elif choice == '2':
            run_tool(['nslookup', ip], ip)
        elif choice == '3':
            cmd = ['tracert', '-d', ip] if platform.system() == 'Windows' else ['traceroute', ip]
            run_tool(cmd, ip)
        elif choice == '4':
            if platform.system() == 'Windows':
                run_tool(['pathping', ip], ip)
            else:
                print(f"{Colors.WARNING}PathPing es exclusivo de Windows. Ejecutando Traceroute...{Colors.RESET}")
                run_tool(['traceroute', ip], ip)
        elif choice == '5':
            grab_banner(ip, device['ports'])
        elif choice == '6':
            break
        else:
            print(f"{Colors.ERROR}Opción inválida.{Colors.RESET}")
        
        input(f"\n{Colors.INFO}Presiona Enter para continuar...{Colors.RESET}")

def save_results(devices):
    filename = "reporte_netxcanner.txt"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*90 + "\n")
            f.write("REPORTE DE ESCANEO DE RED - NETXCANNER CLI v1.1\n")
            f.write("="*90 + "\n\n")
            header = f"{'IP':<18} | {'MAC':<20} | {'FABRICANTE':<25} | {'S.O.':<15} | {'HOSTNAME':<15} | {'PUERTOS':<20}\n"
            f.write(header)
            f.write("-"*90 + "\n")
            for d in devices:
                p_str = ", ".join(map(str, d['ports']))
                line = f"{d['ip']:<18} | {d['mac']:<20} | {d['vendor']:<25} | {d['os']:<15} | {d['hostname']:<15} | {p_str:<20}\n"
                f.write(line)
        print(f"{Colors.SUCCESS}[+] Resultados guardados en {filename}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.ERROR}[-] Error guardando archivo: {str(e)}{Colors.RESET}")

def run_scan_process(target):
    devices = []
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print(f"{Colors.ERROR}[-] Rango de red inválido.{Colors.RESET}")
        return devices

    print(f"\n{Colors.INFO}[*] Escaneando {target}... Por favor espere...{Colors.RESET}\n")
    
    ips = list(net.hosts())
    processed = 0
    total = len(ips)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(scan_device, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            processed += 1
            sys.stdout.write(f"\r{Colors.ACCENT}Progreso: {processed}/{total} hosts escaneados{Colors.RESET}")
            sys.stdout.flush()
            
            data = future.result()
            if data:
                devices.append(data)
                print(f"\n{Colors.SUCCESS}[+] Encontrado: {data['ip']:<15} | MAC: {data['mac']:<17} | SO: {data['os']:<15}{Colors.RESET}")

    print(f"\n\n{Colors.BOLD}[+] Escaneo completado. Se encontraron {len(devices)} dispositivos activos.{Colors.RESET}")
    return devices

def main():
    print_banner()
    if platform.system() == 'Windows':
        os.system('color')
        
    network_suggestion = get_local_network()
    target = input(f" {Colors.BOLD}Introduce el rango de red (ej: {network_suggestion}) > {Colors.RESET}")
    
    if not target:
        target = network_suggestion
    
    devices = run_scan_process(target)
    
    while True:
        print(f"\n{Colors.HEADER}{'IP':<18} | {'MAC':<20} | {'FABRICANTE':<25} | {'S.O.':<15}{Colors.RESET}")
        print("-" * 90)
        for d in devices:
            print(f"{d['ip']:<18} | {d['mac']:<20} | {d['vendor']:<25} | {d['os']:<15}")

        print(f"\n{Colors.ACCENT}{'='*50}{Colors.RESET}")
        print(f" {Colors.BOLD}MENÚ PRINCIPAL{Colors.RESET}")
        print(f" {Colors.ACCENT}{'='*50}{Colors.RESET}")
        print(" 1. Seleccionar dispositivo (Herramientas)")
        print(" 2. Guardar resultados en TXT")
        print(" 3. Volver a escanear")
        print(" 4. Salir")
        
        opt = input(f"\n {Colors.BOLD}Opción > {Colors.RESET}")
        
        if opt == '1':
            ip_select = input(f" {Colors.BOLD}Introduce la IP del dispositivo > {Colors.RESET}")
            selected = next((d for d in devices if d['ip'] == ip_select), None)
            if selected:
                show_device_menu(selected)
            else:
                print(f"{Colors.ERROR}[-] IP no encontrada en los resultados.{Colors.RESET}")
        elif opt == '2':
            save_results(devices)
        elif opt == '3':
            new_target = input(f" {Colors.BOLD}Introduce el rango de red (Enter para usar {target}) > {Colors.RESET}")
            if new_target:
                target = new_target
            devices = run_scan_process(target)
        elif opt == '4':
            print(f"{Colors.INFO}Saliendo...{Colors.RESET}")
            sys.exit(0)
        else:
            print(f"{Colors.ERROR}Opción inválida.{Colors.RESET}")

if __name__ == "__main__":
    main()