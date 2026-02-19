import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import platform
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageTk  # Necesario: pip install pillow

# --- CONFIGURACIÓN DE COLORES (TONOS ROJOS) ---
COLOR_BG_MAIN = "#FFE4E1"   # Fondo general
COLOR_BG_FRAME = "#FABFBF"  # Fondo de paneles
COLOR_ACCENT = "#FF6B6B"    # Botones
COLOR_TEXT = "#8B0000"      # Texto
COLOR_TREE_HEADER = "#FF9999" 
COLOR_TREE_SELECTED = "#FFCCCB"

class SplashScreen:
    """Ventana de bienvenida que muestra el logo."""
    def __init__(self, parent, image_path):
        self.parent = parent
        self.top = tk.Toplevel(parent)
        self.top.overrideredirect(True) # Quitar bordes
        
        try:
            pil_image = Image.open(image_path)
            pil_image = pil_image.resize((400, 300), Image.Resampling.LANCZOS)
            self.img = ImageTk.PhotoImage(pil_image)
            lbl_img = tk.Label(self.top, image=self.img, bg="black")
            lbl_img.pack()
        except Exception as e:
            print(f"No se pudo cargar la imagen del splash: {e}")
            lbl_fallback = tk.Label(self.top, text="NETXCANNER", bg="black", fg="red", font=("Helvetica", 24, "bold"))
            lbl_fallback.pack(pady=20, padx=40)

        lbl_text = tk.Label(self.top, text="NetXcanner v 1.0", bg="black", fg="#FF4444", font=("Helvetica", 16, "bold"))
        lbl_text.pack(pady=(0, 20), fill=tk.X)

        # Centrar
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
        self.win.geometry("450x500")
        self.win.configure(bg=COLOR_BG_MAIN)
        self.win.resizable(False, False)

        # Título
        tk.Label(self.win, text="NetXcanner v 1.0", bg=COLOR_BG_MAIN, fg=COLOR_TEXT, font=("Helvetica", 18, "bold")).pack(pady=15)

        # Características
        frame_features = tk.Frame(self.win, bg=COLOR_BG_FRAME, padx=10, pady=10)
        frame_features.pack(fill=tk.X, padx=20, pady=5)
        
        features_text = """
        Características Principales:
        --------------------------------
        • Escaneo rápido de red (Ping Sweep).
        • Detección de direcciones MAC y Hostname.
        • Interfaz gráfica moderna (Tonos rojos).
        • Splash Screen de inicio personalizado.
        
        Herramientas Incluidas:
        --------------------------------
        • Ping (Conectividad).
        • Tracert (Trazado de ruta).
        • PathPing (Diagnóstico de saltos).
        • NsLookup (Resolución DNS).
        """
        
        tk.Label(frame_features, text=features_text, bg=COLOR_BG_FRAME, fg=COLOR_TEXT, justify=tk.LEFT, font=("Consolas", 10)).pack()

        # Info Programador
        frame_dev = tk.Frame(self.win, bg=COLOR_BG_MAIN)
        frame_dev.pack(fill=tk.X, padx=20, pady=20)
        
        dev_text = """
        Desarrollado por:
        [Tu Nombre / Nombre del Programador]
        
        Contacto:
        tu_correo@ejemplo.com
        
        © 2023 - Todos los derechos reservados
        """
        tk.Label(frame_dev, text=dev_text, bg=COLOR_BG_MAIN, fg="#555555", justify=tk.CENTER, font=("Segoe UI", 10)).pack()

        # Botón Cerrar
        btn_close = tk.Button(self.win, text="Cerrar", command=self.win.destroy, bg=COLOR_ACCENT, fg="white", font=("Segoe UI", 10, "bold"), width=15)
        btn_close.pack(pady=10)

class InteractiveWindow:
    """Ventana de herramientas al hacer doble clic en una IP."""
    def __init__(self, parent, ip):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Herramientas: {ip}")
        self.win.geometry("700x500")
        self.win.configure(bg=COLOR_BG_MAIN)
        self.ip = ip

        tk.Label(self.win, text=f"Diagnóstico y Herramientas", bg=COLOR_BG_MAIN, fg=COLOR_TEXT, font=("Helvetica", 14, "bold")).pack(pady=5)
        tk.Label(self.win, text=f"Objetivo: {ip}", bg=COLOR_BG_MAIN, fg=COLOR_TEXT, font=("Helvetica", 10)).pack()

        self.text_area = tk.Text(self.win, bg="#1E1E1E", fg="#00FF00", font=("Consolas", 10), wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = tk.Frame(self.win, bg=COLOR_BG_MAIN)
        btn_frame.pack(fill=tk.X, pady=10)

        btn_style = {"bg": COLOR_ACCENT, "fg": "white", "relief": tk.FLAT, "font": ("Helvetica", 9, "bold"), "width": 12}
        
        tk.Button(btn_frame, text="Ping", command=self.run_ping, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="NsLookup", command=self.run_nslookup, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="Tracert", command=self.run_tracert, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="PathPing", command=self.run_pathping, **btn_style).pack(side=tk.LEFT, padx=5, expand=True)
        tk.Button(btn_frame, text="Cerrar", command=self.win.destroy, bg="gray", fg="white", font=("Helvetica", 9, "bold"), width=12).pack(side=tk.LEFT, padx=5, expand=True)

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
        self.root.geometry("900x600")
        self.root.configure(bg=COLOR_BG_MAIN)
        
        self.root.withdraw() # Ocultar al inicio
        
        self.scanning = False
        
        self.setup_styles()
        self.create_menu()
        self.create_widgets()
        
        # 1. Mostrar Splash
        self.show_splash()
        # 2. Mostrar App tras 4 segundos
        self.root.after(4000, self.show_main_app)

    def show_splash(self):
        self.splash = SplashScreen(self.root, "NetXcanner v 1.0.png")

    def show_main_app(self):
        self.splash.close()
        self.root.deiconify()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=COLOR_BG_MAIN)
        style.configure("TLabel", background=COLOR_BG_MAIN, foreground=COLOR_TEXT, font=("Segoe UI", 10))
        style.configure("TButton", background=COLOR_ACCENT, foreground="white", font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("TButton", background=[('active', '#CC5555')])
        style.configure("Treeview", background="white", foreground=COLOR_TEXT, fieldbackground="white", font=("Segoe UI", 10), rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background=COLOR_TREE_HEADER, foreground="white")
        style.map("Treeview", background=[('selected', COLOR_TREE_SELECTED)], foreground=[('selected', COLOR_TEXT)])

    def create_menu(self):
        """Crea la barra de menú superior."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Menú Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Salir", command=self.root.quit)
        
        # Menú Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Acerca de...", command=self.show_about)

    def show_about(self):
        """Abre la ventana 'Acerca de'."""
        AboutWindow(self.root)

    def create_widgets(self):
        top_frame = ttk.Frame(self.root, padding="15")
        top_frame.pack(fill=tk.X)
        
        ttk.Label(top_frame, text="Rango de Red:", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        self.ip_range_var = tk.StringVar()
        self.ip_entry = ttk.Entry(top_frame, textvariable=self.ip_range_var, width=25, font=("Segoe UI", 10))
        self.ip_entry.pack(side=tk.LEFT, padx=10)
        
        self.scan_btn = ttk.Button(top_frame, text="ESCANEAR RED", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(top_frame, mode='indeterminate', length=200)
        self.progress.pack(side=tk.LEFT, padx=10)

        columns = ('IP', 'MAC Address', 'Hostname', 'Estado')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        
        self.tree.heading('IP', text='Dirección IP')
        self.tree.heading('MAC Address', text='MAC Address')
        self.tree.heading('Hostname', text='Nombre del Dispositivo')
        self.tree.heading('Estado', text='Estado')
        
        self.tree.column('IP', width=150, anchor=tk.CENTER)
        self.tree.column('MAC Address', width=180, anchor=tk.CENTER)
        self.tree.column('Hostname', width=200, anchor=tk.W)
        self.tree.column('Estado', width=100, anchor=tk.CENTER)
        
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
            InteractiveWindow(self.root, ip)

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
            
        self.status_var.set(f"Escaneando {target}...")
        thread = threading.Thread(target=self.run_scan_logic, args=(target,))
        thread.daemon = True
        thread.start()

    def ping_ip(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '200', str(ip)]
        try:
            subprocess.check_output(command, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0)
            return True
        except: return False

    def get_mac_from_arp(self, ip):
        try:
            command = ['arp', '-a', str(ip)]
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0)
            output = output.decode('utf-8', errors='ignore')
            match = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
            if match: return match.group(1).replace('-', ':').upper()
        except: pass
        return "No Resuelta"

    def get_hostname(self, ip):
        try: return socket.gethostbyaddr(str(ip))[0]
        except: return "Desconocido"

    def run_scan_logic(self, target):
        net = ipaddress.ip_network(target, strict=False)
        with ThreadPoolExecutor(max_workers=50) as executor:
            ips = list(net.hosts())
            results = executor.map(self.ping_ip, ips)
            
            for ip, is_alive in zip(ips, results):
                if not self.scanning: break
                if is_alive:
                    mac = self.get_mac_from_arp(ip)
                    hostname = self.get_hostname(ip)
                    self.root.after(0, self.add_result, str(ip), mac, hostname, "Activo")
        
        self.root.after(0, self.finish_scan)

    def add_result(self, ip, mac, hostname, status):
        self.tree.insert('', tk.END, values=(ip, mac, hostname, status))

    def finish_scan(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.progress.stop()
        self.status_var.set("Escaneo finalizado. Doble clic en una IP para más detalles.")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetXcannerApp(root)
    root.mainloop()