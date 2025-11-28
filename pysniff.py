import socket
import struct
import textwrap
import os
import sys

# --- DICCIONARIOS DE TRADUCCIÓN (LA "INTELIGENCIA") ---

# Mapa de Protocolos IP
PROTO_MAP = {
    1: "ICMP (Ping/Alertas)",
    6: "TCP (Conexión Fiable)",
    17: "UDP (Rápido/Streaming)",
}

# Mapa de Puertos Comunes (Puedes añadir más aquí)
PORT_MAP = {
    20: "FTP-Data (Transferencia Archivos)",
    21: "FTP (Control Archivos)",
    22: "SSH (Consola Segura Remota)",
    23: "Telnet (Consola Insegura)",
    25: "SMTP (Enviar Email)",
    53: "DNS (Búsqueda de Nombres/Dominios)",
    67: "DHCP (Asignación de IP)",
    68: "DHCP (Respuesta)",
    80: "HTTP (Web Insegura - Texto Plano)",
    110: "POP3 (Recibir Email)",
    143: "IMAP (Email Moderno)",
    443: "HTTPS (Web Segura - Candadito)",
    3306: "MySQL (Base de Datos)",
    3389: "RDP (Escritorio Remoto Windows)",
    8080: "HTTP-Proxy (Web Alternativa)",
    5353: "mDNS (Dispositivos Google/Apple)",
}

# --- CONFIGURACIÓN VISUAL ---
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DATA_TAB = '\t\t\t '

def main():
    os_platform = os.name
    print(f"[*] PySniff v3 (Translator Mode) en {os_platform}...")
    
    # --- CONFIGURACIÓN DE RED (IMPORTANTE: PON TU IP AQUÍ SI ESTÁS EN WINDOWS) ---
    # Si dejas esto automático, a veces Windows coge la IP incorrecta.
    # Para mejor resultado, pon tu IP manual ej: HOST_IP = "192.168.1.35"
    HOST_IP = socket.gethostbyname(socket.gethostname()) 
    
    conn = None
    try:
        if os_platform == 'nt':
            print(f"[*] Vinculando a la IP: {HOST_IP}")
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((HOST_IP, 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
    except PermissionError:
        print("[!] Error: Necesitas ser Administrador/Root.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error socket: {e} \n(TIP: En Windows, revisa que HOST_IP sea tu IP de Wifi/Ethernet real)")
        sys.exit(1)

    print("[*] Escuchando y traduciendo tráfico...\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            
            # Manejo Linux (Capa 2)
            ip_data = raw_data
            if os_platform != 'nt':
                dest_mac, src_mac, eth_proto, ip_data = ethernet_frame(raw_data)
                if eth_proto != 8: continue # Solo IPv4

            # --- ANÁLISIS IP (CAPA 3) ---
            try:
                version, header_len, ttl, proto, src, target, data = ipv4_packet(ip_data)
            except:
                continue

            # Traducción del Protocolo
            proto_name = PROTO_MAP.get(proto, f"Otro ({proto})")

            print(f'\n{"="*60}')
            print(f' PAQUETE CAPTURADO: {proto_name}')
            print(f'{"="*60}')
            print(TAB_1 + f'Origen:      {src}')
            print(TAB_1 + f'Destino:     {target}')
            print(TAB_1 + f'TTL:         {ttl} (Saltos de vida restantes)')

            # --- ANÁLISIS TCP (CAPA 4) ---
            if proto == 6:
                src_port, dest_port, seq, ack, urg, ack_f, psh, rst, syn, fin, payload = tcp_segment(data)
                
                # Traducción de Puertos
                src_service = PORT_MAP.get(src_port, "Desconocido/Dinámico")
                dest_service = PORT_MAP.get(dest_port, "Desconocido/Dinámico")
                
                print(TAB_1 + 'INFO DE TRANSPORTE (TCP):')
                print(TAB_2 + f'Puerto Origen:  {src_port} --> [{src_service}]')
                print(TAB_2 + f'Puerto Destino: {dest_port} --> [{dest_service}]')
                
                # Traducción de Banderas (Lo que está pasando)
                flags_desc = []
                if syn: flags_desc.append("INICIANDO (SYN)")
                if fin: flags_desc.append("FINALIZANDO (FIN)")
                if rst: flags_desc.append("ERROR/REINICIO (RST)")
                if psh: flags_desc.append("EMPUJANDO DATOS (PSH)")
                if ack_f: flags_desc.append("CONFIRMADO (ACK)")
                
                print(TAB_2 + f'Estado: {" + ".join(flags_desc)}')

                # Análisis de Seguridad Básico
                if syn and not ack_f:
                    print(TAB_2 + ">> [ALERTA] Intento de conexión nueva detectado")
                if rst:
                    print(TAB_2 + ">> [NOTA] Conexión rechazada o cortada abruptamente")

                # Mostrar Datos
                if len(payload) > 0:
                    print(TAB_1 + 'CONTENIDO (PAYLOAD):')
                    analyze_payload(payload)

            # --- ANÁLISIS UDP (CAPA 4) ---
            elif proto == 17:
                src_port, dest_port, length, payload = udp_segment(data)
                src_service = PORT_MAP.get(src_port, "Desconocido")
                dest_service = PORT_MAP.get(dest_port, "Desconocido")

                print(TAB_1 + 'INFO DE TRANSPORTE (UDP):')
                print(TAB_2 + f'Puerto Origen:  {src_port} ([{src_service}])')
                print(TAB_2 + f'Puerto Destino: {dest_port} ([{dest_service}])')
                
                if len(payload) > 0:
                    print(TAB_1 + 'CONTENIDO (PAYLOAD):')
                    analyze_payload(payload)

    except KeyboardInterrupt:
        print("\n[*] Apagando PySniff...")
        if os_platform == 'nt' and conn:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

# --- FUNCIONES DE AYUDA ---

def analyze_payload(data):
    """ Intenta mostrar datos de forma útil """
    try:
        # Intentamos decodificar como texto (ASCII/UTF-8) para ver si es legible
        text_data = data.decode('utf-8', errors='ignore')
        # Filtramos caracteres que no sean imprimibles para limpiar la salida
        clean_text = ''.join([c if c.isprintable() else '.' for c in text_data])
        
        # Si parece tráfico Web (HTTP), lo formateamos bonito
        if "GET " in text_data or "POST " in text_data or "HTTP/" in text_data:
            print(TAB_2 + ">> [DETECTADO TRÁFICO WEB / HTTP]")
            print(format_multi_line(DATA_TAB, clean_text))
        else:
            # Si no, mostramos Hex + ASCII
            print(format_multi_line(DATA_TAB, data))
            
    except Exception:
        print(format_multi_line(DATA_TAB, data))

# --- FUNCIONES DE DISECCIÓN (NO CAMBIAN) ---
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return None, None, socket.htons(proto), data[14:] # Simplificado para el ejemplo

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H H 2x', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()