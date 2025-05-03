import struct
import socket
import ipaddress
from scapy.all import sniff

# ============================= FUNCIONES COMUNES ============================== #

def compress_ipv6_address(ipv6_address):
    """Comprime una dirección IPv6 a su formato corto"""
    return ipaddress.IPv6Address(ipv6_address).compressed

# ============================= ETHERNET ============================== #

def process_ethernet_header(data):
    """Procesa la cabecera Ethernet"""
    if len(data) < 14:
        print("Error: Trama Ethernet demasiado corta")
        return None

    dest_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = data[12:14]

    print("\n================ ETHERNET HEADER ================")
    print(f"Destino: {':'.join(f'{b:02x}' for b in dest_mac)}")
    print(f"Origen:  {':'.join(f'{b:02x}' for b in src_mac)}")
    print(f"Tipo:    0x{ethertype.hex()}")
    print("================================================")
    
    return ethertype

# ============================= IPv4 ============================== #

def process_ipv4_header(data):
    """Procesa la cabecera IPv4"""
    if len(data) < 34:  # Ethernet(14) + IPv4(20)
        print("Error: Datos insuficientes para IPv4")
        return None
    
    ipv4_data = data[14:34]
    try:
        (version_ihl, tos, total_len, identification, flags_offset,
         ttl, protocol, checksum, src_ip, dest_ip) = struct.unpack("!BBHHHBBH4s4s", ipv4_data)
    except struct.error as e:
        print("Error desempaquetando IPv4:", e)
        return None

    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    flags = (flags_offset >> 13) & 0x07
    offset = flags_offset & 0x1FFF

    src_ip_str = socket.inet_ntoa(src_ip)
    dest_ip_str = socket.inet_ntoa(dest_ip)

    print("\n================== IPv4 HEADER ==================")
    print(f"Versión:          {version}")
    print(f"IHL:              {ihl} bytes")
    print(f"TOS:              0x{tos:02x}")
    print(f"Longitud Total:   {total_len} bytes")
    print(f"Identificación:   0x{identification:04x}")
    print(f"Flags:            0b{flags:03b}")
    print(f"Offset:           {offset}")
    print(f"TTL:              {ttl}")
    print(f"Protocolo:        {protocol}")
    print(f"Checksum:         0x{checksum:04x}")
    print(f"Origen:           {src_ip_str}")
    print(f"Destino:          {dest_ip_str}")
    print("================================================")
    
    return protocol

# ============================= ICMPv4 ============================== #

def process_icmpv4_header(data):
    """Procesa la cabecera ICMPv4"""
    if len(data) < 42:
        print("Error: Datos insuficientes para ICMPv4")
        return

    icmp_data = data[34:42]
    icmp_type, code, checksum = struct.unpack("!BBH", icmp_data[:4])
    payload = icmp_data[4:]

    print("\n================== ICMPv4 HEADER =================")
    print(f"Tipo:            {icmp_type}")
    print(f"Código:          {code}")
    print(f"Checksum:        0x{checksum:04x}")
    print(f"Payload:         {payload.hex()}")
    print("================================================")

# ============================= ARP ============================== #

def process_arp_header(data):
    """Procesa la cabecera ARP"""
    if len(data) < 28:
        print("Error: Datos insuficientes para ARP")
        return

    arp_data = data[14:42]
    (
        hw_type, proto_type, hw_size, proto_size,
        opcode, sender_mac, sender_ip, target_mac, target_ip
    ) = struct.unpack("!HHBBH6s4s6s4s", arp_data)

    print("\n=================== ARP HEADER ===================")
    print(f"Tipo Hardware:   {hw_type}")
    print(f"Tipo Protocolo:  0x{proto_type:04x}")
    print(f"Operación:       {'Request' if opcode == 1 else 'Reply'}")
    print(f"MAC Origen:      {':'.join(f'{b:02x}' for b in sender_mac)}")
    print(f"IP Origen:       {socket.inet_ntoa(sender_ip)}")
    print(f"MAC Destino:     {':'.join(f'{b:02x}' for b in target_mac)}")
    print(f"IP Destino:      {socket.inet_ntoa(target_ip)}")
    print("================================================")

# ============================= TCP ============================== #

def process_tcp_header(data, ipv6=False):
    """Procesa la cabecera TCP"""
    offset = 54 if ipv6 else 34
    if len(data) < offset + 20:
        print("Error: Datos insuficientes para TCP")
        return

    tcp_data = data[offset:offset+20]
    try:
        (src_port, dest_port, seq, ack, offset_flags,
         window, checksum, urg_ptr) = struct.unpack("!HHIIHHHH", tcp_data)
    except struct.error as e:
        print("Error desempaquetando TCP:", e)
        return

    data_offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x1FF

    print("\n=================== TCP HEADER ===================")
    print(f"Puerto Origen:   {src_port}")
    print(f"Puerto Destino:  {dest_port}")
    print(f"Secuencia:       0x{seq:08x}")
    print(f"ACK:             0x{ack:08x}")
    print(f"Flags:           0b{flags:09b}")
    print(f"Ventana:         {window}")
    print(f"Checksum:        0x{checksum:04x}")
    print(f"Urgente:         {urg_ptr}")
    print("================================================")

# ============================= IPv6 ============================== #

def process_ipv6_header(data):
    """Procesa la cabecera IPv6"""
    if len(data) < 54:
        print("Error: Datos insuficientes para IPv6")
        return None

    ipv6_data = data[14:54]
    try:
        (version_tc_fl, payload_len, next_header, hop_limit,
         src_ip, dest_ip) = struct.unpack("!IHBB16s16s", ipv6_data)
    except struct.error as e:
        print("Error desempaquetando IPv6:", e)
        return None

    version = (version_tc_fl >> 28) & 0x0F
    traffic_class = (version_tc_fl >> 20) & 0xFF
    flow_label = version_tc_fl & 0xFFFFF

    src_ip_str = socket.inet_ntop(socket.AF_INET6, src_ip)
    dest_ip_str = socket.inet_ntop(socket.AF_INET6, dest_ip)

    print("\n================== IPv6 HEADER ==================")
    print(f"Versión:          {version}")
    print(f"Clase Tráfico:    0x{traffic_class:02x}")
    print(f"Etiqueta Flujo:   0x{flow_label:05x}")
    print(f"Longitud Payload: {payload_len}")
    print(f"Next Header:      {next_header}")
    print(f"Hop Limit:        {hop_limit}")
    print(f"Origen:           {compress_ipv6_address(src_ip_str)}")
    print(f"Destino:          {compress_ipv6_address(dest_ip_str)}")
    print("================================================")
    
    return next_header

# ============================= UDP/IPv6 y DNS ============================== #

def process_udp_ipv6(data):
    """Procesa cabecera UDP en IPv6"""
    if len(data) < 54 + 8:
        print("Error: Datos insuficientes para UDP")
        return
    
    udp_data = data[54:54+8]
    try:
        src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_data)
    except struct.error as e:
        print("Error desempaquetando UDP:", e)
        return

    print("\n================== UDP HEADER (IPv6) =================")
    print(f"Puerto Origen:  {src_port}")
    print(f"Puerto Destino: {dest_port}")
    print(f"Longitud:       {length}")
    print(f"Checksum:       0x{checksum:04x}")
    print("====================================================")

    # Procesar DNS si es puerto 53
    if src_port == 53 or dest_port == 53:
        process_dns(data, 54 + 8)

def process_dns(data, offset):
    """Procesa cabecera DNS"""
    if len(data) < offset + 12:
        print("Error: Datos DNS incompletos")
        return
    
    dns_header = data[offset:offset+12]
    try:
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_header)
    except struct.error as e:
        print("Error desempaquetando DNS:", e)
        return

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    rcode = flags & 0xF

    print("\n==================== DNS HEADER ====================")
    print(f"Transaction ID:  0x{tid:04x}")
    print(f"Flags:           0x{flags:04x}")
    print(f"  QR: {'Respuesta' if qr else 'Consulta'}")
    print(f"  OPCODE: {opcode} | AA: {'Sí' if aa else 'No'}")
    print(f"  TC: {'Sí' if tc else 'No'} | RD: {'Sí' if rd else 'No'}")
    print(f"  RA: {'Sí' if ra else 'No'} | RCODE: {rcode}")
    print(f"Preguntas: {qdcount} | Respuestas: {ancount}")
    print(f"Autoridad: {nscount} | Adicionales: {arcount}")
    print("====================================================")

# ============================= ICMPv6 ============================== #

def process_icmpv6_header(data):
    """Procesa la cabecera ICMPv6"""
    if len(data) < 58:
        print("Error: Datos insuficientes para ICMPv6")
        return

    icmp_data = data[54:58]
    icmp_type, code, checksum = struct.unpack("!BBH", icmp_data)

    print("\n================= ICMPv6 HEADER =================")
    print(f"Tipo:            {icmp_type}")
    print(f"Código:          {code}")
    print(f"Checksum:        0x{checksum:04x}")
    print("================================================")

# ============================= MAIN ============================== #

def process_packet(packet):
    try:
        raw_data = bytes(packet)
        print("\n" + "="*60 + "\nPaquete capturado:")

        ethertype = process_ethernet_header(raw_data)

        if ethertype == b'\x08\x00':  # IPv4
            protocol = process_ipv4_header(raw_data)
            if protocol == 1:    # ICMP
                process_icmpv4_header(raw_data)
            elif protocol == 6:  # TCP
                process_tcp_header(raw_data)
            elif protocol == 17: # UDP
                pass  # UDP IPv4 no implementado

        elif ethertype == b'\x86\xdd':  # IPv6
            next_header = process_ipv6_header(raw_data)
            if next_header == 6:    # TCP
                process_tcp_header(raw_data, ipv6=True)
            elif next_header == 17: # UDP
                process_udp_ipv6(raw_data)
            elif next_header == 58: # ICMPv6
                process_icmpv6_header(raw_data)

        elif ethertype == b'\x08\x06':  # ARP
            process_arp_header(raw_data)

    except Exception as e:
        print(f"Error procesando paquete: {str(e)}")

if __name__ == "__main__":
    print("Iniciando sniffer... (Ctrl+C para detener)")
    sniff(prn=process_packet, store=0, iface="Wi-Fi")