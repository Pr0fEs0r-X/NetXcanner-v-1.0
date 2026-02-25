import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import platform
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageTk
import urllib.request
import sys
import os


def resource_path(relative_path):
    """ Obtiene la ruta absoluta del recurso, funciona para dev y para PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
# -----------------------------------------


COLOR_BG_MAIN = "#1E1E1E"   # Fondo principal oscuro
COLOR_BG_FRAME = "#2D2D2D"  # Fondo de paneles
COLOR_ACCENT = "#0078D4"    # Azul Cibernético
COLOR_TEXT = "#FFFFFF"      # Texto Blanco
COLOR_TREE_HEADER = "#3E3E42" 
COLOR_TREE_SELECTED = "#094771"
COLOR_CONTRAST = "#E0E0E0"

class SplashScreen:
    """Ventana de bienvenida que muestra el logo."""
    def __init__(self, parent, image_path):
        self.parent = parent
        self.top = tk.Toplevel(parent)
        self.top.overrideredirect(True)
        self.top.configure(bg="black")
        
        try:
            pil_image = Image.open(image_path)
            pil_image = pil_image.resize((300, 300), Image.Resampling.LANCZOS)
            self.img = ImageTk.PhotoImage(pil_image)
            lbl_img = tk.Label(self.top, image=self.img, bg="black")
            lbl_img.pack()
        except Exception as e:
            print(f"No se pudo cargar la imagen del splash: {e}")
            lbl_fallback = tk.Label(self.top, text="NETXCANNER", bg="black", fg=COLOR_ACCENT, font=("Consolas", 24, "bold"))
            lbl_fallback.pack(pady=20, padx=40)

        lbl_text = tk.Label(self.top, text="NetXcanner v 1.0", bg="black", fg="#CCCCCC", font=("Consolas", 16, "bold"))
        lbl_text.pack(pady=(0, 20), fill=tk.X)

        self.top.update_idletasks()
        width = self.top.winfo_width()
        height = self.top.winfo_height()
        x = (self.top.winfo_screenwidth() // 2) - (width // 2)
        y = (self.top.winfo_screenheight() // 2) - (height // 2)
        self.top.geometry(f'{width}x{height}+{x}+{y}')

    def close(self):
        self.top.destroy()

class AboutWindow:
    """Ventana "Acerca de" con información del programa."""
    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title("Acerca de NetXcanner")
        self.win.geometry("450x600") 
        self.win.configure(bg=COLOR_BG_MAIN)
        self.win.resizable(False, False)

        tk.Label(self.win, text="NetXcanner v 1.0", bg=COLOR_BG_MAIN, fg=COLOR_ACCENT, font=("Consolas", 18, "bold")).pack(pady=15)

        frame_features = tk.Frame(self.win, bg=COLOR_BG_FRAME, padx=10, pady=10)
        frame_features.pack(fill=tk.X, padx=20, pady=5)
        
        features_text = """
        Características Principales:
        --------------------------------
        • Detección de SO (TTL Fingerprint).
        • Detección de Fabricante (OUI).
        • Escaneo rápido de red.
        • Detección de Puertos Abiertos.
        • Exportación de resultados a TXT.
        
        Nota sobre Detección de SO:
        --------------------------------
        Se basa en el TTL del paquete:
        Windows (TTL 128)
        Linux/Android/Mac/iOS (TTL 64)
        """
        
        tk.Label(frame_features, text=features_text, bg=COLOR_BG_FRAME, fg=COLOR_CONTRAST, justify=tk.LEFT, font=("Consolas", 10)).pack()

        frame_dev = tk.Frame(self.win, bg=COLOR_BG_MAIN)
        frame_dev.pack(fill=tk.X, padx=20, pady=20)
        
        dev_text = """
        Desarrollado por:
        [Rodolfo Hernandez Baz]
        
        Contacto:
        rodolfohbaz@gmail.com
        """
        tk.Label(frame_dev, text=dev_text, bg=COLOR_BG_MAIN, fg="#888888", justify=tk.CENTER, font=("Segoe UI", 10)).pack()

        btn_close = tk.Button(self.win, text="Cerrar", command=self.win.destroy, bg=COLOR_ACCENT, fg="white", font=("Segoe UI", 10, "bold"), width=15, relief=tk.FLAT)
        btn_close.pack(pady=10)

class InteractiveWindow:
    """Ventana de herramientas y datos al hacer doble clic en una IP."""
    def __init__(self, parent, ip, device_data=None):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Herramientas: {ip}")
        self.win.geometry("550x400") # Tamaño aumentado ligeramente para mejor proporción
        self.win.configure(bg=COLOR_BG_MAIN)
        self.ip = ip
        self.device_data = device_data if device_data else {}

        
        btn_frame = tk.Frame(self.win, bg=COLOR_BG_MAIN)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10, padx=10)

        btn_style = {"bg": COLOR_ACCENT, "fg": "white", "relief": tk.FLAT, "font": ("Consolas", 10, "bold"), "width": 12, "pady": 5}
        
        
        tk.Button(btn_frame, text="Ping", command=self.run_ping, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="NsLookup", command=self.run_nslookup, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="Tracert", command=self.run_tracert, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="PathPing", command=self.run_pathping, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="Cerrar", command=self.win.destroy, bg="#555555", fg="white", font=("Consolas", 10, "bold"), width=12).pack(side=tk.LEFT, padx=5, expand=True)

       
        tk.Label(self.win, text=f"Diagnóstico y Herramientas", bg=COLOR_BG_MAIN, fg=COLOR_ACCENT, font=("Consolas", 14, "bold")).pack(pady=5)
        tk.Label(self.win, text=f"Objetivo: {ip}", bg=COLOR_BG_MAIN, fg=COLOR_CONTRAST, font=("Consolas", 10)).pack()

        
        info_frame = tk.LabelFrame(self.win, text=" Información Detectada ", bg=COLOR_BG_FRAME, fg=COLOR_ACCENT, font=("Consolas", 10, "bold"), padx=10, pady=5)
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        lbl_style = {"bg": COLOR_BG_FRAME, "fg": COLOR_CONTRAST, "font": ("Consolas", 9), "anchor": "w"}
        
        
        row1 = tk.Frame(info_frame, bg=COLOR_BG_FRAME)
        row1.pack(fill=tk.X, pady=2)
        tk.Label(row1, text=f"MAC: {self.device_data.get('mac', 'N/A')}", **lbl_style).pack(side=tk.LEFT, padx=5)
        tk.Label(row1, text=f"Fabricante: {self.device_data.get('vendor', 'N/A')}", **lbl_style).pack(side=tk.LEFT, padx=15)

        
        row2 = tk.Frame(info_frame, bg=COLOR_BG_FRAME)
        row2.pack(fill=tk.X, pady=2)
        tk.Label(row2, text=f"S.O.: {self.device_data.get('os', 'N/A')}", **lbl_style).pack(side=tk.LEFT, padx=5)
        tk.Label(row2, text=f"Hostname: {self.device_data.get('hostname', 'N/A')}", **lbl_style).pack(side=tk.LEFT, padx=15)

        
        ports = self.device_data.get('ports', [])
        ports_str = ", ".join(map(str, ports)) if ports else "Ninguno encontrado"
        
        ports_row = tk.Frame(info_frame, bg=COLOR_BG_FRAME)
        ports_row.pack(fill=tk.X, pady=2)
        tk.Label(ports_row, text=f"Puertos Abiertos: {ports_str}", bg=COLOR_BG_FRAME, fg="#00FF00", font=("Consolas", 10, "bold"), anchor="w").pack(fill=tk.X, padx=5)

        
        self.text_area = tk.Text(self.win, bg="#0E0E0E", fg="#00FF00", font=("Consolas", 10), wrap=tk.WORD, insertbackground="white")
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

   
    def run_ping(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, f"Iniciando Ping a {self.ip}...\n\n")
        if platform.system() == 'Windows':
            command = ['ping', '-n', '10', self.ip]
        else:
            command = ['ping', '-c', '10', self.ip]
        threading.Thread(target=self._exec_command, args=(command,), daemon=True).start()

    def run_nslookup(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, f"Consultando DNS para {self.ip}...\n\n")
        threading.Thread(target=self._exec_command, args=(['nslookup', self.ip],), daemon=True).start()

    def run_tracert(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, f"Ejecutando Tracert a {self.ip}...\n(Esto puede tardar unos segundos)\n\n")
        cmd = 'tracert' if platform.system() == 'Windows' else 'traceroute'
        command = [cmd, '-d', self.ip]
        threading.Thread(target=self._exec_command, args=(command,), daemon=True).start()

    def run_pathping(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, f"Ejecutando PathPing a {self.ip}...\n(ADVERTENCIA: Este proceso tarda varios minutos)\n\n")
        if platform.system() == 'Windows':
            command = ['pathping', self.ip]
            threading.Thread(target=self._exec_command, args=(command,), daemon=True).start()
        else:
            self.text_area.insert(tk.END, "Comando 'pathping' exclusivo de Windows.\nIntentando 'traceroute'...\n")
            self.run_tracert()

    def _exec_command(self, command):
        try:
            startupinfo = None
            if platform.system() == 'Windows':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                       text=True, encoding='cp850', errors='replace', startupinfo=startupinfo)
            
            for line in process.stdout:
                self.text_area.insert(tk.END, line)
                self.text_area.see(tk.END)
                self.text_area.update_idletasks()
                
        except Exception as e:
            self.text_area.insert(tk.END, f"Error ejecutando comando: {str(e)}")

class NetXcannerApp:
    """Aplicación Principal."""
    def __init__(self, root):
        self.root = root
        self.root.title("NetXcanner v 1.0")
        self.root.geometry("950x500") 
        self.root.configure(bg=COLOR_BG_MAIN)
        
        self.root.withdraw()
        self.scanning = False
        self.devices_data = {} # Diccionario para guardar datos completos por IP
        
        self.setup_styles()
        self.create_menu()
        self.create_widgets()
        
        self.show_splash()
        self.root.after(4000, self.show_main_app)

    def show_splash(self):
        img_path = resource_path("logo.png")
        self.splash = SplashScreen(self.root, img_path)

    def show_main_app(self):
        self.splash.close()
        self.root.deiconify()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=COLOR_BG_MAIN)
        style.configure("TLabel", background=COLOR_BG_MAIN, foreground=COLOR_TEXT, font=("Segoe UI", 10))
        style.configure("TButton", background=COLOR_ACCENT, foreground="white", font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("TButton", background=[('active', '#005A9E')])
        style.configure("Treeview", background=COLOR_BG_FRAME, foreground=COLOR_TEXT, fieldbackground=COLOR_BG_FRAME, font=("Consolas", 10), rowheight=28)
        style.configure("Treeview.Heading", font=("Consolas", 10, "bold"), background=COLOR_TREE_HEADER, foreground=COLOR_TEXT)
        style.map("Treeview", background=[('selected', COLOR_TREE_SELECTED)], foreground=[('selected', COLOR_TEXT)])

    def create_menu(self):
        menubar = tk.Menu(self.root, bg=COLOR_BG_FRAME, fg=COLOR_TEXT)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLOR_BG_FRAME, fg=COLOR_TEXT)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Guardar Resultados...", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.root.quit)
        help_menu = tk.Menu(menubar, tearoff=0, bg=COLOR_BG_FRAME, fg=COLOR_TEXT)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Acerca de...", command=self.show_about)

    def show_about(self):
        AboutWindow(self.root)

    def create_widgets(self):
        top_frame = ttk.Frame(self.root, padding="15")
        top_frame.pack(fill=tk.X)
        
        ttk.Label(top_frame, text="Rango de Red:", font=("Consolas", 11, "bold")).pack(side=tk.LEFT)
        self.ip_range_var = tk.StringVar()
        self.ip_entry = ttk.Entry(top_frame, textvariable=self.ip_range_var, width=25, font=("Consolas", 10))
        self.ip_entry.pack(side=tk.LEFT, padx=10)
        
        self.scan_btn = ttk.Button(top_frame, text="ESCANEAR RED", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=10)

        self.save_btn = ttk.Button(top_frame, text="GUARDAR TXT", command=self.save_results)
        self.save_btn.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(top_frame, mode='indeterminate', length=200)
        self.progress.pack(side=tk.LEFT, padx=10)

        columns = ('IP', 'MAC Address', 'Fabricante', 'S.O. / Tipo', 'Hostname', 'Estado')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        
        self.tree.heading('IP', text='Dirección IP')
        self.tree.heading('MAC Address', text='MAC Address')
        self.tree.heading('Fabricante', text='Fabricante (OUI)')
        self.tree.heading('S.O. / Tipo', text='S.O. Detectado')
        self.tree.heading('Hostname', text='Nombre del Dispositivo')
        self.tree.heading('Estado', text='Estado')
        
        self.tree.column('IP', width=130, anchor=tk.CENTER)
        self.tree.column('MAC Address', width=140, anchor=tk.CENTER)
        self.tree.column('Fabricante', width=140, anchor=tk.W)
        self.tree.column('S.O. / Tipo', width=130, anchor=tk.CENTER)
        self.tree.column('Hostname', width=150, anchor=tk.W)
        self.tree.column('Estado', width=80, anchor=tk.CENTER)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        self.tree.bind("<Double-1>", self.on_double_click)

        self.status_var = tk.StringVar(value="Listo. Doble clic en una IP para herramientas avanzadas.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.CENTER)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        self.detect_local_network()

    def detect_local_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split('.')
            self.ip_range_var.set(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        except:
            self.ip_range_var.set("192.168.1.0/24")

    def on_double_click(self, event):
        item = self.tree.selection()
        if item:
            ip = self.tree.item(item[0])['values'][0]
            device_info = self.devices_data.get(ip, {})
            InteractiveWindow(self.root, ip, device_info)

    def start_scan(self):
        if self.scanning: return
        target = self.ip_range_var.get()
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            messagebox.showerror("Error", "Rango inválido")
            return

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.progress.start(10)
        
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.devices_data = {}
            
        self.status_var.set(f"Escaneando {target}...")
        thread = threading.Thread(target=self.run_scan_logic, args=(target,))
        thread.daemon = True
        thread.start()

    def ping_and_get_ttl(self, ip):
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

    def get_mac_from_arp(self, ip):
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

    def get_vendor(self, mac):
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

    def get_hostname(self, ip):
        try: 
            return socket.gethostbyaddr(str(ip))[0]
        except: 
            return "N/A"

    def guess_os(self, ttl, vendor):
        if ttl is None: return "Desconocido"
        vendor_low = vendor.lower()
        if ttl <= 64:
            if "apple" in vendor_low: return "iOS / macOS"
            elif "samsung" in vendor_low or "xiaomi" in vendor_low or "huawei" in vendor_low or "lg" in vendor_low or "motorola" in vendor_low: return "Android"
            else: return "Linux / Unix"
        elif ttl <= 128: return "Windows"
        elif ttl > 128 and ttl <= 255: return "Router / Switch"
        return "Desconocido"

    def scan_common_ports(self, ip):
        common_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389, 8080]
        open_ports = []
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((str(ip), port))
                if result == 0: open_ports.append(port)
                s.close()
            except: pass
        return open_ports

    def scan_single_device(self, ip):
        is_alive, ttl = self.ping_and_get_ttl(ip)
        if is_alive:
            mac = self.get_mac_from_arp(ip)
            vendor = "Desconocido"
            if mac: vendor = self.get_vendor(mac)
            else: mac = "No Resuelta"
            os_name = self.guess_os(ttl, vendor)
            hostname = self.get_hostname(ip)
            ports = self.scan_common_ports(ip)
            return {
                'ip': str(ip), 'mac': mac, 'vendor': vendor,
                'os': os_name, 'hostname': hostname,
                'status': "Activo", 'ports': ports
            }
        return None

    def run_scan_logic(self, target):
        net = ipaddress.ip_network(target, strict=False)
        ips = list(net.hosts())
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(self.scan_single_device, ips)
            for result in results:
                if not self.scanning: break
                if result: self.root.after(0, self.add_result, result)
        self.root.after(0, self.finish_scan)

    def add_result(self, data):
        self.devices_data[data['ip']] = data
        self.tree.insert('', tk.END, values=(
            data['ip'], data['mac'], data['vendor'],
            data['os'], data['hostname'], data['status']
        ))

    def finish_scan(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.progress.stop()
        self.status_var.set("Escaneo finalizado. Doble clic en una IP para ver detalles y herramientas.")

    def save_results(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showwarning("Aviso", "No hay datos para guardar.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")])
        if not file_path: return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("=" * 100 + "\nREPORTE DE ESCANEO DE RED\n" + "=" * 100 + "\n\n")
                header = f"{'IP':<18} | {'MAC':<20} | {'FABRICANTE':<25} | {'S.O.':<15} | {'HOSTNAME':<20} | {'ESTADO':<10} | {'PUERTOS':<20}\n"
                f.write(header + "-" * 120 + "\n")
                for item in items:
                    v = self.tree.item(item)['values']
                    ports = self.devices_data.get(v[0], {}).get('ports', [])
                    p_str = ", ".join(map(str, ports)) if ports else "N/A"
                    f.write(f"{v[0]:<18} | {v[1]:<20} | {v[2]:<25} | {v[3]:<15} | {v[4]:<20} | {v[5]:<10} | {p_str:<20}\n")
            messagebox.showinfo("Éxito", "Guardado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetXcannerApp(root)
    root.mainloop()