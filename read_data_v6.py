import struct
import socket
import ipaddress
from scapy.all import sniff

# ---------------- Funciones para IPv6 ---------------- #

def compress_ipv6_address(ipv6_address):
    """
    Comprime y formatea correctamente una dirección IPv6.
    """
    return ipaddress.IPv6Address(ipv6_address).compressed

def process_ipv6_header(data):
    """
    Procesa la cabecera IPv6 a partir de un paquete (se asume trama Ethernet + IPv6).
    Se extraen y muestran la versión, Traffic Class, Flow Label, Payload Length,
    Next Header, Hop Limit, y las direcciones IPv6 de origen y destino.
    """
    # Comprobar que haya suficientes bytes para Ethernet (14) + IPv6 (40)
    if len(data) < 14 + 40:
        print("Error: Datos insuficientes para una cabecera IPv6 válida.")
        return

    # La cabecera IPv6 ocupa 40 bytes a partir del byte 14
    ipv6_data = data[14:14+40]
    try:
        # Desempaquetar la cabecera IPv6
        version_tc_fl, payload_length, next_header, hop_limit, src_ip, dest_ip = struct.unpack("!I H B B 16s 16s", ipv6_data)
    except struct.error as e:
        print("Error desempaquetando cabecera IPv6:", e)
        return

    # Extraer campos
    version = (version_tc_fl >> 28) & 0xF
    traffic_class = (version_tc_fl >> 20) & 0xFF
    flow_label = version_tc_fl & 0xFFFFF

    # Convertir direcciones de bytes a texto usando inet_ntop
    try:
        src_ip_str = socket.inet_ntop(socket.AF_INET6, src_ip)
        dest_ip_str = socket.inet_ntop(socket.AF_INET6, dest_ip)
    except Exception as e:
        print("Error convirtiendo direcciones IPv6:", e)
        return

    traffic_class_bin = f"{traffic_class:08b}"
    priority_bits = traffic_class_bin[:3]
    # Se extraen bits para retardo, rendimiento y fiabilidad
    delay_bit = traffic_class_bin[3]
    throughput_bit = traffic_class_bin[4]
    reliability_bit = traffic_class_bin[5]
    unused_bits = traffic_class_bin[6:]

    priority_map = {
        "000": "De rutina",
        "001": "Prioritario",
        "010": "Inmediato",
        "011": "Relámpago",
        "100": "Invalidación relámpago",
        "101": "Proceso crítico o de emergencia",
        "110": "Control de trabajo de Internet",
        "111": "Control de red"
    }
    priority = priority_map.get(priority_bits, "Desconocido")
    delay = "Bajo" if delay_bit == "1" else "Normal"
    throughput = "Alto" if throughput_bit == "1" else "Normal"
    reliability = "Alta" if reliability_bit == "1" else "Normal"

    # Mapeo del campo Next Header (de forma básica)
    next_header_map = {
        1: "ICMPv4",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
        118: "STP",
        121: "SMP"
    }
    next_header_str = next_header_map.get(next_header, f"Desconocido ({next_header})")

    print("\n-------------------------- IPv6 Header --------------------------")
    print(f"Versión:           {version}")
    print(f"Traffic Class:     {traffic_class} (Binario: {traffic_class_bin})")
    print(f"  - Prioridad:     {priority_bits} ({priority})")
    print(f"  - Retardo:       {delay_bit} ({delay})")
    print(f"  - Rendimiento:   {throughput_bit} ({throughput})")
    print(f"  - Fiabilidad:    {reliability_bit} ({reliability})")
    print(f"  - Reservados:    {unused_bits}")
    print(f"Flow Label:        {flow_label}")
    print(f"Payload Lenght:    {payload_length} bytes")
    print(f"Next Header:       {next_header} ({next_header_str})")
    print(f"Hop Limit:         {hop_limit}")
    print(f"Src IP Address:    {compress_ipv6_address(src_ip_str)}")
    print(f"Dest IP Address:   {compress_ipv6_address(dest_ip_str)}")
    print("------------------------------------------------------------------")

def process_icmpv6_header(data):
    """
    Procesa la cabecera ICMPv6 (se asume que la trama contiene Ethernet + IPv6 + ICMPv6)
    para extraer Tipo, Código y Checksum.
    """
    # Ethernet (14) + IPv6 (40) = 54 bytes; mínimo para cabecera ICMPv6 (4 bytes)
    if len(data) < 14 + 40 + 4:
        print("Error: Datos insuficientes para una cabecera ICMPv6 válida.")
        return

    # La cabecera ICMPv6 empieza en el byte 54
    icmp_data = data[14+40:14+40+4]
    try:
        icmp_type, icmp_code, icmp_checksum = struct.unpack("!B B H", icmp_data)
    except struct.error as e:
        print("Error desempaquetando cabecera ICMPv6:", e)
        return

    # Clasificación básica de mensajes ICMPv6
    if icmp_type < 128:
        tipo_msg = "Mensaje de error"
    else:
        tipo_msg = "Mensaje informativo"

    icmp_type_map = {
        1: "Destino inalcanzable",
        2: "Paquete demasiado grande",
        3: "Tiempo excedido",
        128: "Solicitud de eco (ping)",
        129: "Respuesta de eco (pong)",
        133: "Solicitud de Router",
        134: "Anuncio de Router",
        135: "Solicitud de Vecino",
        136: "Anuncio de Vecino",
        137: "Redireccionamiento"
    }
    icmp_type_str = icmp_type_map.get(icmp_type, f"Desconocido ({icmp_type})")

    print("\n-------------------------- ICMPv6 Header --------------------------")
    print(f"Tipo:         {icmp_type} ({tipo_msg}) - {icmp_type_str}")
    print(f"Código:       {icmp_code}")
    print(f"Checksum:     0x{icmp_checksum:04x}")
    print("--------------------------------------------------------------------")

# ---------------- Funciones existentes para Ethernet, IPv4, ICMPv4, ARP y TCP ---------------- #

def process_ethernet_header(data):
    if len(data) < 14:
        print("Error: Datos demasiado pequeños para una trama Ethernet válida.")
        return

    dest_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = data[12:14]

    dest_mac_str = ":".join(f"{byte:02x}" for byte in dest_mac)
    src_mac_str = ":".join(f"{byte:02x}" for byte in src_mac)
    ethertype_str = f"0x{ethertype.hex()}"

    print('\n------- Ethernet Header -------')
    print(f"MAC Destino: {dest_mac_str}")
    print(f"MAC Origen:  {src_mac_str}")
    print(f"Ethertype:   {ethertype_str}")

def process_ipv4_header(data):
    if len(data) < 14 + 20:
        print("Error: Datos insuficientes para una cabecera IPv4 válida.")
        return

    ipv4_data = data[14:14+20]
    try:
        (version_ihl, tos, total_length, identification, flags_frag_offset,
         ttl, protocol, checksum, src_ip, dest_ip) = struct.unpack("!BBHHHBBHII", ipv4_data)
    except struct.error as e:
        print("Error desempaquetando cabecera IPv4:", e)
        return

    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    flags = (flags_frag_offset >> 13) & 0b111
    fragment_offset = flags_frag_offset & 0x1FFF

    src_ip_str = ".".join(map(str, src_ip.to_bytes(4, 'big')))
    dest_ip_str = ".".join(map(str, dest_ip.to_bytes(4, 'big')))

    print("\n------- IPv4 Header -------")
    print(f"Version:           {version}")
    print(f"IHL:               {ihl//4} ({ihl} bytes)")
    print(f"TOS:               {format(tos, '08b')}")
    print(f"Total Length:      {total_length} bytes")
    print(f"Identification:    {format(identification, '016b')}")
    print(f"Flags:             {format(flags, '03b')}")
    print(f"Fragment Offset:   {format(fragment_offset, '013b')}")
    print(f"TTL:               {ttl}")
    print(f"Protocol:          {'ICMP' if protocol == 1 else protocol}")
    print(f"Header Checksum:   {format(checksum, '016b')}")
    print(f"Src IP:            {src_ip_str}")
    print(f"Dest IP:           {dest_ip_str}")

def process_icmpv4_header(data):
    if len(data) < 14 + 20 + 8:
        print("Error: Datos insuficientes para una cabecera ICMPv4 válida.")
        return

    icmp_data = data[14+20:14+20+8]
    icmp_type = icmp_data[0]
    icmp_code = icmp_data[1]
    checksum = int.from_bytes(icmp_data[2:4], 'big')
    identifier = int.from_bytes(icmp_data[4:6], 'big')
    sequence_number = int.from_bytes(icmp_data[6:8], 'big')

    type_messages = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        5: 'Redirect',
        8: 'Echo Request',
        11: 'Time Exceeded'
    }
    code_messages = {
        0: 'Network unreachable',
        1: 'Host unreachable',
        2: 'Protocol unreachable',
        3: 'Port unreachable'
    }

    print("\n------- ICMPv4 Header -------")
    print(f"Type:              {icmp_type} ({type_messages.get(icmp_type, 'Otro')})")
    print(f"Code:              {icmp_code} ({code_messages.get(icmp_code, 'Desconocido')})")
    print(f"Checksum:          0x{checksum:04x}")
    print(f"Identifier:        {identifier}")
    print(f"Sequence Number:   {sequence_number}")

def process_arp_header(data):
    # Se asume que la trama ARP completa (sin la cabecera Ethernet) tiene al menos 28 bytes
    if len(data) < 28:
        print("Error: Datos insuficientes para una cabecera ARP.")
        return

    hardware_type = int.from_bytes(data[0:2], 'big')
    protocol_type = data[2:4]
    protocol_type_str = f"0x{protocol_type.hex()}"
    hardware_size = data[4]
    protocol_size = data[5]
    opcode = int.from_bytes(data[6:8], 'big')
    sender_mac = data[8:14]
    sender_ip = data[14:18]
    target_mac = data[18:24]
    target_ip = data[24:28]

    sender_mac_str = ":".join(f"{byte:02x}" for byte in sender_mac)
    sender_ip_str = ".".join(map(str, sender_ip))
    target_mac_str = ":".join(f"{byte:02x}" for byte in target_mac)
    target_ip_str = ".".join(map(str, target_ip))

    print("\n------- ARP Header -------")
    print(f"Hardware Type: {hardware_type}")
    print(f"Protocol Type: {protocol_type_str}")
    print(f"Hardware Size: {hardware_size}")
    print(f"Protocol Size: {protocol_size}")
    print(f"Opcode:        {opcode}")
    print(f"Sender MAC:    {sender_mac_str}")
    print(f"Sender IP:     {sender_ip_str}")
    print(f"Target MAC:    {target_mac_str}")
    print(f"Target IP:     {target_ip_str}")

def process_tcp_header(data):
    if len(data) < 14 + 20 + 20:
        print("Error: Datos insuficientes para una cabecera TCP.")
        return

    tcp_start = 14 + 20  # Ethernet + IPv4
    tcp_data = data[tcp_start:tcp_start+20]
    try:
        (src_port, dest_port, sequence, ack_number,
         offset_reserved_flags, window, checksum, urgent_pointer) = struct.unpack("!HHIIHHHH", tcp_data)
    except struct.error as e:
        print("Error desempaquetando cabecera TCP:", e)
        return

    data_offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF

    ns  = (flags >> 8) & 1
    cwr = (flags >> 7) & 1
    ece = (flags >> 6) & 1
    urg = (flags >> 5) & 1
    ack = (flags >> 4) & 1
    psh = (flags >> 3) & 1
    rst = (flags >> 2) & 1
    syn = (flags >> 1) & 1
    fin = flags & 1

    print("\n------- TCP Header -------")
    print(f"Puerto de Origen:    {src_port}")
    print(f"Puerto de Destino:    {dest_port}")
    print(f"N° Secuencia:         {sequence}")
    print(f"N° Acuse de recibo:   {ack_number}")
    print(f"Longitud de Cabecera: {data_offset} bytes")
    print("Banderas TCP:")
    print(f"  NS:  {'Set' if ns else 'Not set'}")
    print(f"  CWR: {'Set' if cwr else 'Not set'}")
    print(f"  ECE: {'Set' if ece else 'Not set'}")
    print(f"  URG: {'Set' if urg else 'Not set'}")
    print(f"  ACK: {'Set' if ack else 'Not set'}")
    print(f"  PSH: {'Set' if psh else 'Not set'}")
    print(f"  RST: {'Set' if rst else 'Not set'}")
    print(f"  SYN: {'Set' if syn else 'Not set'}")
    print(f"  FIN: {'Set' if fin else 'Not set'}")
    print(f"Tamaño Ventana de Recepción: {window}")
    print(f"Suma de Verificación: 0x{checksum:04x}")
    print(f"Puntero Urgente:         {urgent_pointer}")

# ---------------- Callback de Scapy para procesamiento en tiempo real ---------------- #

def process_packet(packet):
    data = bytes(packet)
    print("\n======================================")
    print("Nuevo paquete capturado")

    if len(data) < 14:
        print("Paquete inválido (demasiado corto).")
        return

    # Procesar la cabecera Ethernet
    process_ethernet_header(data)

    ethertype = data[12:14]
    
    if ethertype == b'\x08\x00':  # IPv4
        process_ipv4_header(data)
        if len(data) >= 14 + 20:
            protocol = data[14+9]  # En IPv4, el campo 'protocol' se encuentra en el byte 23 (14+9)
            if protocol == 1:
                process_icmpv4_header(data)
            elif protocol == 6:
                process_tcp_header(data)
            else:
                print("\nProtocolo IPv4 no procesado en este ejemplo.")
    elif ethertype == b'\x86\xdd':  # IPv6
        process_ipv6_header(data)
        # Extraer el campo "Next Header" de IPv6, que se halla a partir de la cabecera (offset: 14 + 6)
        if len(data) >= 14 + 40:
            next_header = data[14+6]
            if next_header == 58:  # ICMPv6
                process_icmpv6_header(data)
            else:
                print("\nProtocolo IPv6 no procesado en este ejemplo.")
    elif ethertype == b'\x08\x06':  # ARP
        # La cabecera ARP viene después de los 14 bytes Ethernet (suponemos al menos 28 bytes)
        process_arp_header(data[14:14+28])
    else:
        print("\nTipo de protocolo no reconocido o no implementado.")

# ---------------- Configuración de la captura en tiempo real ---------------- #

def main():
    iface = "Wi-Fi"  # Interfaz determinada
    print(f"Iniciando captura en tiempo real en la interfaz '{iface}'...\n")
    sniff(prn=process_packet, iface=iface, store=0)

if __name__ == '__main__':
    main()
