## NetXcanner v1.0

NetXcanner es una herramienta de escaneo de red multiplataforma, rápida y visualmente amigable, desarrollada en Python. Permite descubrir dispositivos en una red local, identificar sus sistemas operativos, fabricantes y proporcionar herramientas de diagnóstico integradas.

Captura de pantalla de NetXcanner

## 🚀 Características Principales

    * Escaneo Rápido: Utiliza multihilo (ThreadPoolExecutor) para escanear rangos de red completos (ej. /24) en segundos.
    * Detección de SO (TTL Fingerprint): Identifica si el dispositivo corre Windows, Linux, Android o iOS basándose en el Time-To-Live (TTL) del paquete.
    * Identificación de Fabricante (OUI): Resuelve la dirección MAC para mostrar el fabricante del dispositivo (Ej: Samsung, Apple, TP-Link).
    * Multiplataforma: Funciona nativamente en Windows, Linux y macOS.
    * Herramientas de Diagnóstico: Ventana interactiva al hacer doble clic sobre una IP con acceso a:
    
    ------------------------------
        - Ping
        - NsLookup
        - Tracert / Traceroute
        - PathPing (Solo Windows)
        - Exportación de Datos: Guarda los resultados del escaneo en un archivo de texto formateado (.txt).
        - Interfaz Gráfica Moderna: Diseño personalizado con pantalla de bienvenida (Splash Screen).

## 📋 Requisitos Previos

    * Python 3.8 o superior.
    * Sistema Operativo: Windows, Linux (Debian/Ubuntu/Arch/Fedora) o macOS.
    * Dependencia externa: Pillow (para el manejo de imágenes).

## ⚙️ Instalación y Uso (Desde Código Fuente)

   `-` Clonar el repositorio:

  `-` git clone https://github.com/tu_usuario/netxcanner.gitcd netxcanner

   ### Instalar dependencias:

    -- pip install pillow

    -- Ejecutar la aplicación:Asegúrate de tener el archivo de imagen NetXcanner v 1.0.png en la misma carpeta que el script.

    -- python main.py

## 🛠️ Compilación a Ejecutable (PyInstaller)

Si deseas compilar la aplicación para distribuirla como un archivo ejecutable (.exe en Windows o binario en Linux/Mac), sigue estos pasos: 


#### 1. Instalar PyInstaller

pip install pyinstaller


 
#### 2. Compilar en Windows 

El comando debe incluir la imagen del splash screen usando el separador ;. 
bash
 
  
 
pyinstaller --onefile --windowed --add-data "NetXcanner v 1.0.png;." main.py
 
 
 
#### 3. Compilar en Linux / macOS 

El comando es similar, pero el separador de rutas es :. 
bash
 
  
 
pyinstaller --onefile --windowed --add-data "NetXcanner v 1.0.png:." main.py
 
 
 

Nota: El ejecutable generado se encontrará dentro de la carpeta dist/. 
💻 Tecnologías Utilizadas 

     * Lenguaje: Python 3
     * GUI: Tkinter (ttk)
     * Procesamiento de Imágenes: Pillow (PIL)
     * Red: ipaddress, socket, subprocess
     * Concurrencia: ThreadPoolExecutor
     

## 👤 Autor 

Rodolfo Hernandez Baz 

     Email: rodolfohbaz@gmail.com 
     GitHub: [Tu Usuario de GitHub]
     

## 📜 Licencia 

Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles. 
