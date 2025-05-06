import struct
import socket
import ipaddress
from scapy.all import sniff
import sys
from datetime import datetime

# Configuración global
packet_count = 0
MAX_PACKETS = 50
LOG_FILE = "packet_capture.txt"

# Redirigir la salida estándar
class Tee:
    def __init__(self, *files):
        self.files = files
    
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()
    
    def flush(self):
        for f in self.files:
            f.flush()

def setup_logging():
    log_file = open(LOG_FILE, 'w')
    original_stdout = sys.stdout
    sys.stdout = Tee(original_stdout, log_file)
    return log_file

# ------------------------- Funciones de Procesamiento ------------------------- #

def process_ethernet_header(data):
    if len(data) < 14:
        print("Error: Datos insuficientes para cabecera Ethernet")
        return None  # Retornar None si no hay suficientes datos

    dest_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = data[12:14]

    print('\n-------------------------- Ethernet Header --------------------------')
    print(f"MAC Destino: {':'.join(f'{byte:02x}' for byte in dest_mac)}")
    print(f"MAC Origen:  {':'.join(f'{byte:02x}' for byte in src_mac)}")
    print(f"Ethertype:   0x{ethertype.hex()}")
    
    return ethertype  # Retornar el tipo Ethernet para procesamiento posterior

def process_ipv4_header(data):
    if len(data) < 34:  # Ethernet(14) + IPv4(20)
        print("Error: Datos insuficientes para cabecera IPv4")
        return

    ip_header = data[14:34]
    try:
        version_ihl, tos, total_len, ident, flags_frag, ttl, proto, checksum, src_ip, dest_ip = \
            struct.unpack('!BBHHHBBH4s4s', ip_header)
    except struct.error as e:
        print(f"Error desempaquetando IPv4: {e}")
        return

    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    flags = flags_frag >> 13
    frag_offset = flags_frag & 0x1FFF

    print("\n-------------------------- IPv4 Header --------------------------")
    print(f"Versión:            {version}")
    print(f"IHL:                {ihl} bytes")
    print(f"TOS:                0x{tos:02x}")
    print(f"Longitud Total:     {total_len}")
    print(f"Identificación:     0x{ident:04x}")
    print(f"Flags:              0x{flags:01x}")
    print(f"Offset Fragmento:   {frag_offset}")
    print(f"TTL:                {ttl}")
    print(f"Protocolo:          {proto} ({'ICMP' if proto == 1 else 'TCP' if proto == 6 else 'UDP' if proto == 17 else 'Otro'})")
    print(f"Checksum:           0x{checksum:04x}")
    print(f"IP Origen:          {socket.inet_ntoa(src_ip)}")
    print(f"IP Destino:         {socket.inet_ntoa(dest_ip)}")

    # Procesar el protocolo de nivel superior
    if proto == 1:  # ICMPv4
        process_icmpv4_header(data, ihl)
    elif proto == 6:  # TCP
        process_tcp_header(data, 4, ihl)
    elif proto == 17:  # UDP
        process_udp_header(data, ihl)

def process_ipv6_header(data):
    if len(data) < 54:  # Ethernet(14) + IPv6(40)
        print("Error: Datos insuficientes para cabecera IPv6")
        return

    ip6_header = data[14:54]
    try:
        version_tc_flow, payload_len, next_header, hop_limit, src_ip, dest_ip = \
            struct.unpack('!IHBB16s16s', ip6_header)
    except struct.error as e:
        print(f"Error desempaquetando IPv6: {e}")
        return

    version = version_tc_flow >> 28
    traffic_class = (version_tc_flow >> 20) & 0xFF
    flow_label = version_tc_flow & 0xFFFFF

    print("\n-------------------------- IPv6 Header --------------------------")
    print(f"Versión:            {version}")
    print(f"Clase Tráfico:      0x{traffic_class:02x}")
    print(f"Etiqueta Flujo:     0x{flow_label:05x}")
    print(f"Longitud Payload:   {payload_len}")
    print(f"Siguiente Cabecera: {next_header} ({'ICMPv6' if next_header == 58 else 'TCP' if next_header == 6 else 'UDP' if next_header == 17 else 'Otro'})")
    print(f"Límite Saltos:      {hop_limit}")
    print(f"IP Origen:          {ipaddress.IPv6Address(src_ip).compressed}")
    print(f"IP Destino:         {ipaddress.IPv6Address(dest_ip).compressed}")

    # Procesar el protocolo de nivel superior
    if next_header == 58:  # ICMPv6
        process_icmpv6_header(data)
    elif next_header == 6:  # TCP
        process_tcp_header(data, 6)
    elif next_header == 17:  # UDP
        process_udp_header(data)

def process_icmpv4_header(data, ip_header_len):
    if len(data) < 14 + ip_header_len + 8:
        print("Error: Datos insuficientes para cabecera ICMPv4")
        return

    icmp_header = data[14+ip_header_len:14+ip_header_len+8]
    try:
        icmp_type, icmp_code, checksum = struct.unpack('!BBH', icmp_header[:4])
    except struct.error as e:
        print(f"Error desempaquetando ICMPv4: {e}")
        return

    print("\n-------------------------- ICMPv4 Header --------------------------")
    print(f"Tipo:               {icmp_type} ({'Echo Reply' if icmp_type == 0 else 'Echo Request' if icmp_type == 8 else 'Otro'})")
    print(f"Código:             {icmp_code}")
    print(f"Checksum:           0x{checksum:04x}")

    # Mostrar datos adicionales para Echo Request/Reply
    if icmp_type in (0, 8):
        identifier, seq_num = struct.unpack('!HH', icmp_header[4:8])
        print(f"Identificador:      0x{identifier:04x}")
        print(f"Número Secuencia:   {seq_num}")

def process_icmpv6_header(data):
    if len(data) < 62:  # Ethernet(14) + IPv6(40) + ICMPv6(8)
        print("Error: Datos insuficientes para cabecera ICMPv6")
        return

    icmp6_header = data[54:62]
    try:
        icmp6_type, icmp6_code, checksum = struct.unpack('!BBH', icmp6_header[:4])
    except struct.error as e:
        print(f"Error desempaquetando ICMPv6: {e}")
        return

    print("\n-------------------------- ICMPv6 Header --------------------------")
    print(f"Tipo:               {icmp6_type} ({'Echo Request' if icmp6_type == 128 else 'Echo Reply' if icmp6_type == 129 else 'Otro'})")
    print(f"Código:             {icmp6_code}")
    print(f"Checksum:           0x{checksum:04x}")

    # Mostrar datos adicionales para Echo Request/Reply
    if icmp6_type in (128, 129):
        identifier, seq_num = struct.unpack('!HH', icmp6_header[4:8])
        print(f"Identificador:      0x{identifier:04x}")
        print(f"Número Secuencia:   {seq_num}")

def process_tcp_header(data, ip_version, ip_header_len=0):
    tcp_start = 14 + (ip_header_len if ip_version == 4 else 40)
    if len(data) < tcp_start + 20:
        print("Error: Datos insuficientes para cabecera TCP")
        return

    tcp_header = data[tcp_start:tcp_start+20]
    try:
        src_port, dest_port, seq, ack, offset_reserved, flags, window, checksum, urg_ptr = \
            struct.unpack('!HHLLBBHHH', tcp_header)
    except struct.error as e:
        print(f"Error desempaquetando TCP: {e}")
        return

    data_offset = (offset_reserved >> 4) * 4
    ns_flag = (offset_reserved & 0x01)
    cwr_flag = (flags & 0x80) >> 7
    ece_flag = (flags & 0x40) >> 6
    urg_flag = (flags & 0x20) >> 5
    ack_flag = (flags & 0x10) >> 4
    psh_flag = (flags & 0x08) >> 3
    rst_flag = (flags & 0x04) >> 2
    syn_flag = (flags & 0x02) >> 1
    fin_flag = (flags & 0x01)

    print("\n-------------------------- TCP Header --------------------------")
    print(f"Puerto Origen:      {src_port}")
    print(f"Puerto Destino:     {dest_port}")
    print(f"Número Secuencia:   {seq}")
    print(f"Número ACK:         {ack}")
    print(f"Longitud Cabecera:  {data_offset} bytes")
    print(f"Flags:             ")
    print(f"  NS:  {ns_flag}  CWR: {cwr_flag}  ECE: {ece_flag}  URG: {urg_flag}")
    print(f"  ACK: {ack_flag}  PSH: {psh_flag}  RST: {rst_flag}  SYN: {syn_flag}  FIN: {fin_flag}")
    print(f"Ventana:            {window}")
    print(f"Checksum:           0x{checksum:04x}")
    print(f"Puntero Urgente:    {urg_ptr}")

def process_udp_header(data, ip_header_len=0):
    udp_start = 14 + ip_header_len
    if len(data) < udp_start + 8:
        print("Error: Datos insuficientes para cabecera UDP")
        return

    udp_header = data[udp_start:udp_start+8]
    try:
        src_port, dest_port, length, checksum = struct.unpack('!HHHH', udp_header)
    except struct.error as e:
        print(f"Error desempaquetando UDP: {e}")
        return

    print("\n-------------------------- UDP Header --------------------------")
    print(f"Puerto Origen:      {src_port}")
    print(f"Puerto Destino:     {dest_port}")
    print(f"Longitud:           {length}")
    print(f"Checksum:           0x{checksum:04x}")

    # Procesar DNS si es tráfico en puerto 53
    if src_port == 53 or dest_port == 53:
        process_dns_header(data[udp_start+8:udp_start+8+12])

def process_dns_header(data):
    if len(data) < 12:
        print("Error: Datos insuficientes para cabecera DNS")
        return

    try:
        trans_id, flags, questions, answers, auth_rr, add_rr = struct.unpack('!HHHHHH', data[:12])
    except struct.error as e:
        print(f"Error desempaquetando DNS: {e}")
        return

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF

    print("\n-------------------------- DNS Header --------------------------")
    print(f"ID Transacción:     0x{trans_id:04x}")
    print(f"Flags:              0x{flags:04x}")
    print(f"  QR: {qr}  OPCODE: {opcode}  AA: {aa}  TC: {tc}  RD: {rd}  RA: {ra}  Z: {z}  RCODE: {rcode}")
    print(f"Preguntas:          {questions}")
    print(f"Respuestas:         {answers}")
    print(f"RR Autoridad:       {auth_rr}")
    print(f"RR Adicionales:     {add_rr}")

def process_arp_header(data):
    if len(data) < 14 + 28:
        print("Error: Datos insuficientes para cabecera ARP")
        return

    arp_header = data[14:42]
    try:
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip = \
            struct.unpack('!HHBBH6s4s6s4s', arp_header)
    except struct.error as e:
        print(f"Error desempaquetando ARP: {e}")
        return

    print("\n-------------------------- ARP Header --------------------------")
    print(f"Tipo Hardware:      {hw_type} ({'Ethernet' if hw_type == 1 else 'Otro'})")
    print(f"Tipo Protocolo:     0x{proto_type:04x}")
    print(f"Tamaño Hardware:    {hw_size}")
    print(f"Tamaño Protocolo:   {proto_size}")
    print(f"Operación:          {opcode} ({'Request' if opcode == 1 else 'Reply' if opcode == 2 else 'Otro'})")
    print(f"MAC Origen:         {':'.join(f'{b:02x}' for b in sender_mac)}")
    print(f"IP Origen:          {socket.inet_ntoa(sender_ip)}")
    print(f"MAC Destino:        {':'.join(f'{b:02x}' for b in target_mac)}")
    print(f"IP Destino:         {socket.inet_ntoa(target_ip)}")

def process_rarp_header(data):
    if len(data) < 14 + 28:
        print("Error: Datos insuficientes para cabecera RARP")
        return

    rarp_header = data[14:42]
    try:
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip = \
            struct.unpack('!HHBBH6s4s6s4s', rarp_header)
    except struct.error as e:
        print(f"Error desempaquetando RARP: {e}")
        return

    print("\n-------------------------- RARP Header -------------------------")
    print(f"Tipo Hardware:      {hw_type} ({'Ethernet' if hw_type == 1 else 'Otro'})")
    print(f"Tipo Protocolo:     0x{proto_type:04x}")
    print(f"Tamaño Hardware:    {hw_size}")
    print(f"Tamaño Protocolo:   {proto_size}")
    print(f"Operación:          {opcode} ({'Request' if opcode == 3 else 'Reply' if opcode == 4 else 'Otro'})")
    print(f"MAC Origen:         {':'.join(f'{b:02x}' for b in sender_mac)}")
    print(f"IP Origen:          {socket.inet_ntoa(sender_ip) if proto_size == 4 else 'IPv6'}")
    print(f"MAC Destino:        {':'.join(f'{b:02x}' for b in target_mac)}")
    print(f"IP Destino:         {socket.inet_ntoa(target_ip) if proto_size == 4 else 'IPv6'}")

# ------------------------- Función Principal ------------------------- #

def process_packet(packet):
    global packet_count
    
    if packet_count >= MAX_PACKETS:
        print(f"\nSe ha alcanzado el limite de {MAX_PACKETS} paquetes.")
        return
    
    packet_count += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"\n=============== Paquete #{packet_count} - {timestamp} ===============")
    
    data = bytes(packet)
    if len(data) < 14:
        print("Paquete demasiado corto")
        return

    # Procesar cabecera Ethernet y obtener el tipo
    ethertype = process_ethernet_header(data)

    # Determinar protocolo de nivel superior
    if ethertype == b'\x08\x00':    # IPv4
        process_ipv4_header(data)
    elif ethertype == b'\x86\xdd':  # IPv6
        process_ipv6_header(data)
    elif ethertype == b'\x08\x06':  # ARP/RARP
        # Verificar si es ARP (opcode 1-2) o RARP (opcode 3-4)
        if len(data) >= 14 + 8:  # Suficiente para leer el opcode
            opcode = int.from_bytes(data[20:22], 'big')
            if opcode in (1, 2):  # ARP
                process_arp_header(data)
            elif opcode in (3, 4):  # RARP
                process_rarp_header(data)
            else:
                print("Operación ARP/RARP desconocida")
    else:
        print("Protocolo no reconocido")

def main():
    global packet_count
    packet_count = 0
    
    interfaz = "Ethernet"
    log_file = setup_logging()
    
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"=== Inicio de captura - {start_time} ===")
    print(f"Interfaz: {interfaz}")
    print(f"Limite: {MAX_PACKETS} paquetes")
    print(f"Archivo: {LOG_FILE}")
    print("="*60 + "\n")
    
    try:
        # icmp, tcp, udp, arp, tcp port 80-53, ip6, ip
        sniff(filter="icmp", prn=process_packet, iface=interfaz, store=0, count=MAX_PACKETS)
    except KeyboardInterrupt:
        print("\nCaptura interrumpida por usuario")
    except Exception as e:
        print(f"\nError: {str(e)}")
    finally:
        sys.stdout = sys.__stdout__
        log_file.close()
        
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n=== Captura finalizada - {end_time} ===")
        print(f"Paquetes capturados: {packet_count}")
        print(f"Resultados guardados en: {LOG_FILE}")

if __name__ == '__main__':
    main()