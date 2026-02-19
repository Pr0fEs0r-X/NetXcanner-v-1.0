
<b>📝 Descripción</b>

NetXcanner es una aplicación de escritorio autónoma diseñada para el análisis y monitoreo de redes locales (LAN). Desarrollada íntegramente en Python, ofrece una interfaz gráfica moderna con una estética de tonos rojos, permitiendo a los administradores de red y entusiastas realizar un escaneo rápido y eficiente de todos los dispositivos conectados.

La aplicación proporciona información crítica en tiempo real, como direcciones IP activas, direcciones MAC, nombres de host (Hostname) e integra herramientas de diagnóstico de red esenciales accesibles con un solo clic.
✨ Características Principales

    Escaneo de Red (Ping Sweep): Detecta automáticamente todos los hosts activos en la subred local.
    Resolución de Datos: Obtiene direcciones MAC y nombres de host (DNS) de los dispositivos detectados.
    Splash Screen Interactivo: Presentación visual inicial con duración de 4 segundos.
    Herramientas de Diagnóstico Integradas:
        Ping: Verificación de conectividad continua.
        Tracert: Trazado de ruta hasta el destino.
        PathPing: Análisis de pérdida de paquetes en saltos intermedios.
        NsLookup: Consulta de registros DNS.
    Interfaz Intuitiva: Visualización en tabla con opciones de interacción mediante doble clic.

<b>🚀 Instalación y Ejecució</b>

Sigue estos pasos para ejecutar la aplicación en tu máquina local.
Prerrequisitos

    Python 3.x instalado en tu sistema.
    (Opcional) Npcap instalado si se desean utilizar funciones de bajo nivel, aunque la versión actual utiliza comandos nativos del sistema para mayor compatibilidad.

Pasos

    Clona el repositorio:

    git clone https://github.com/tu-usuario/netxcanner.gitcd netxcanner

    Instala las dependencias necesarias:La aplicación utiliza Pillow para el manejo de imágenes en la pantalla de bienvenida.

    pip install pillow

    Ejecuta la aplicación:Asegúrate de que la imagen NetXcanner v 1.0.png esté en el mismo directorio que el script.

    python NetXcanner.py

<b>⚙️ Técnicas Utilizadas</b>

El desarrollo de NetXcanner combina múltiples técnicas de programación y protocolos de red para lograr su funcionamiento:
1. Interfaz Gráfica (GUI)

    Tkinter & ttk: Se utilizó la librería estándar tkinter para la estructura de la ventana, junto con ttk para widgets modernos (tablas, barras de progreso) y estilos personalizados mediante ttk.Style para lograr la estética de tonos rojos.
    Multi-hilo (Threading): El escaneo de red y la ejecución de comandos de diagnóstico se realizan en hilos secundarios (threading.Thread y ThreadPoolExecutor). Esto es crucial para evitar que la interfaz gráfica se congele mientras se procesan largas listas de IPs o comandos lentos como tracert.

2. Escaneo de Red (Network Scanning)

    Ping Sweep Nativo: En lugar de depender de librerías externas complejas como Scapy, la aplicación utiliza el módulo subprocess para ejecutar comandos ping nativos del sistema operativo. Esto garantiza alta compatibilidad y evita problemas de permisos ("Raw Sockets") en Windows.
    ThreadPoolExecutor: Se implementa un pool de 50 hilos concurrentes para realizar pings a múltiples direcciones IP simultáneamente, reduciendo drásticamente el tiempo de escaneo en redes /24.

3. Resolución de Direcciones (Discovery)

    ARP Caching: Para obtener las direcciones MAC, la aplicación interactúa con la tabla ARP del sistema operativo. Ejecuta el comando arp -a y utiliza Expresiones Regulares (Regex) para parsear la salida de texto y extraer las direcciones MAC dinámicamente.
    DNS Reverso: Se utiliza la librería socket de Python (socket.gethostbyaddr) para resolver las direcciones IP a nombres de host, facilitando la identificación de dispositivos.

4. Procesamiento de Comandos

    Pipes y Subprocess: Las herramientas interactivas (Ping, Tracert, etc.) se ejecutan mediante subprocess.Popen. Se utiliza stdout=PIPE para capturar la salida en tiempo real y creationflags=CREATE_NO_WINDOW para ejecutar los comandos de consola sin mostrar ventanas negras emergentes en Windows, integrando el resultado limpiamente en la interfaz de la aplicación.

<b>👨‍💻 Autor</b>

Rodolfo Hernandez Baz   AkA Pr@fEs0r X

    Desarrollado como herramienta de apoyo para administradores de red.
    Contacto: [rodolfohbaz@gmail.com]

<b>📜 Licencia</b>

Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.
