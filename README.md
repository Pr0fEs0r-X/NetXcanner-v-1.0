<b>🛡️ NetXScanner  v 1.,0 (ARP Scanner)</b> 
by <b><center>⚠️ by Rodolfo Hernández Baz</b> </center>

Una herramienta de línea de comandos ligera y eficiente escrita en Python para descubrir dispositivos conectados a tu red local.

<b>📋 Tabla de Contenidos</b>

    --Características
    --Requisitos Previos
    --Instalación
    --Uso
    --Cómo Funciona
    --Advertencia Legal

<b>✨ Características Principales</b>

    -- Detección Automática de Red: Identifica automáticamente el rango de IP local (subnet) sin configuración manual.
    -- Descubrimiento ARP: Utiliza paquetes ARP para detectar dispositivos incluso si no responden a pings (ICMP).
    -- Resolución de Hostnames: Intenta resolver el nombre del dispositivo (NetBIOS/DNS).
    -- Direcciones MAC: Muestra la dirección física (MAC) de cada dispositivo conectado.
    -- Argumentos Personalizables: Permite especificar manualmente el rango de red a escanear mediante flags.
    Interfaz Clara: Salida tabulada y fácil de leer en la terminal.

<b>⚙️ Requisitos Previos</b>

<b>Antes de ejecutar la aplicación, asegúrate de cumplir con lo siguiente:</b>

    --Python 3.x instalado en tu sistema.
    
    --Permisos de Administrador:
        Windows: Ejecutar la terminal (CMD/PowerShell) como Administrador.
        Linux/macOS: Usar sudo.
        
    --Npcap (Windows): Es necesario instalar Npcap para que Scapy pueda inyectar paquetes. (Marca la opción "Install Npcap in WinPcap API-compatible Mode" durante la instalación).
<br>
<b>🚀 Instalación</b>

<b>Sigue estos pasos para configurar el entorno:</b>

    1.- Clona el repositorio:

    git clone https://github.com/tu-usuario/network-scanner.gitcd network-scanner

    2.- Crea un entorno virtual (Opcional pero recomendado):

    python -m venv venv# Windowsvenv\Scripts\activate# Linux/Macsource venv/bin/activate

    3.- Instala las dependencias:

    pip install scapy
<br>
<b>💻 Uso</b>

<b>El script es flexible y permite tanto el escaneo automático como el manual.</b>

--> Ver la ayuda (-h)

<b>Para ver todas las opciones disponibles:</b>

python network_scanner.py -h
<br>
 
<b>usage: network_scanner.py [-h] [-t RANGO]</b>
<br>
Escáner de Red Local (ARP Scanner). Detecta dispositivos activos, sus
direcciones MAC y nombres de host.

<br>

<b>options:</b>
  -h, --help  show this help message and exit
  -t RANGO    Especifica el rango de red a escanear en formato CIDR (ej:
              192.168.1.0/24). Si no se especifica, se detecta automáticamente.
 
<br><b>-= Escaneo Automático =-</b>

Detecta tu IP actual y escanea toda tu subred automáticamente: 

Windows (CMD como Admin): 
cmd
 
python network_scanner.py

<br><br>

****************************
<b>Linux / macOS:</b> 
****************************
<br>
bash
 
sudo python3 network_scanner.py
 
 <br>
<b>-= Escaneo Dirigido =- </b>

Especifica un rango de red concreto usando notación CIDR: 
bash
 <br>
 
[*] Tu IP local parece ser: 192.168.1.50
[*] Escaneando la red: 192.168.1.0/24 ...

<br> <br>
 
<b>🔩 ¿Cómo Funciona?</b> 

Esta herramienta se basa en el protocolo ARP (Address Resolution Protocol): 

    -- Broadcast: El script envía un paquete Ethernet de difusión (broadcast) preguntando: "¿Quién tiene la IP X?". 
    -- Respuesta: Los dispositivos activos en la red responden con su dirección MAC: "Yo tengo la IP X y mi MAC es Y". 
    -- Resolución de Nombres: Paralelamente, el script utiliza socket para realizar consultas DNS inversas y obtener el nombre del host (hostname). 
<br>
Este método es más rápido y fiable en redes locales que un escaneo tradicional de ping (ICMP), ya que la mayoría de los firewalls bloquean los pings, pero rara vez bloquean el tráfico ARP necesario para la comunicación de red. 
<br><br>

<b><center>⚠️ Advertencia Legal</b> </center>

    Nota: Esta herramienta ha sido creada con fines educativos y de auditoría de redes propias. El uso de este software para escanear redes ajenas sin autorización expresa es ilegal. 
    El usuario es el único responsable del uso que haga de esta herramienta. Úsala siempre en tus propias redes o en redes donde tengas permiso.
<br>
   <b><center>⚠️ Rodolfo Hernandez Baz - rodolfohbaz@gmail.com</b> </center>
