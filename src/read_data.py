import struct
import os
import socket
import ipaddress

def compress_ipv6_address(ipv6_address):
    """
    Utiliza la biblioteca estándar para comprimir direcciones IPv6 correctamente.
    """
    return ipaddress.IPv6Address(ipv6_address).compressed

def read_ethernet_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            bin_data = data.read(14)
            if len(bin_data) < 14:
                raise ValueError("Archivo demasiado pequeño para una trama Ethernet válida.")
            
            dest_mac, src_mac, ethertype = struct.unpack("!6s6s2s", bin_data)
            print('\n------- Ethernet Header -------')
            print(f"MAC Destino: {':'.join(f'{b:02x}' for b in dest_mac)}")
            print(f"MAC Origen: {':'.join(f'{b:02x}' for b in src_mac)}")
            print(f"Ethertype: 0x{ethertype.hex()}")
    except Exception as e:
        print(f"Error: {e}")

def read_ipv4_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(14)  # Skip Ethernet header
            bin_data = data.read(20)  # Read IPv4 minimum header
            if len(bin_data) < 20:
                raise ValueError("Archivo demasiado pequeño para contener una cabecera IPv4 válida.")

            # Unpack IPv4 header
            version_ihl, tos, total_length, identification, flags_frag_offset, ttl, protocol, checksum, src_ip, dest_ip = struct.unpack(
                "!BBHHHBBHII", bin_data)

            version = version_ihl >> 4
            ihl = (version_ihl & 0x0F) * 4

            # Extract flags and fragment offset
            flags = (flags_frag_offset >> 13) & 0b111
            fragment_offset = flags_frag_offset & 0x1FFF

            # Split flags
            reserved_flag = (flags >> 2) & 0x1
            df_flag = (flags >> 1) & 0x1
            mf_flag = flags & 0x1

            # Convert IPs to readable format
            src_ip_str = ".".join(map(str, src_ip.to_bytes(4, 'big')))
            dest_ip_str = ".".join(map(str, dest_ip.to_bytes(4, 'big')))

            # Convert values to binary for display
            identification_bin = format(identification, '016b')
            flags_bin = format(flags, '03b')
            fragment_offset_bin = format(fragment_offset, '013b')
            checksum_bin = format(checksum, '016b')

            print("\n-------------------------- IPV4 Header --------------------------")
            print(f"Version:           {version}")
            print(f"IHL:               {ihl // 4} ({ihl} bytes)")
            print(f"TOS:               {format(tos, '08b')}")
            print(f"                   Precedence (000):              Routine")
            print(f"                   Delay (Bit 3: {tos >> 3 & 0x1}):         {'Low' if tos >> 3 & 0x1 else 'Normal'}")
            print(f"                   Throughput (Bit 4: {tos >> 4 & 0x1}):    {'High' if tos >> 4 & 0x1 else 'Normal'}")
            print(f"                   Reliability (Bit 5: {tos >> 5 & 0x1}):   {'High' if tos >> 5 & 0x1 else 'Normal'}")
            print(f"                   Reserved (Bits 6-7: {format(tos >> 6, '02b')})")
            print(f"Total Length:      {total_length} bytes")
            print(f"Identification:    {identification_bin}")
            print(f"Flags:             {flags_bin} ", end="")

            if reserved_flag:
                print("Reserved bit set (Should be 0).")
            elif df_flag and mf_flag:
                print("DF and MF both set (Invalid).")
            elif df_flag:
                print("Not Divisible, no fragmentation allowed.")
            elif mf_flag:
                print("More Fragments, not the last one.")
            else:
                print("Last fragment.")

            print(f"Fragment Offset:   {fragment_offset_bin}")
            print(f"TTL:               {ttl}")
            print(f"Protocol:          {'ICMP' if protocol == 1 else protocol}")
            print(f"Header Checksum:   {checksum_bin}")
            print(f"Src IP:            {src_ip_str}")
            print(f"Dest IP:           {dest_ip_str}")
            print("---------------------------------------------------------------")

    except Exception as e:
        print(f"Error: {e}")

def read_ipv6_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(14)  # Skip Ethernet header
            bin_data = data.read(40)
            if len(bin_data) < 40:
                raise ValueError("Archivo demasiado pequeño para una cabecera IPv6 válida.")
            
            version_tc_fl, payload_length, next_header, hop_limit, src_ip, dest_ip = struct.unpack("!I H B B 16s 16s", bin_data)
            
            version = (version_tc_fl >> 28) & 0xF
            traffic_class = (version_tc_fl >> 20) & 0xFF
            flow_label = version_tc_fl & 0xFFFFF
            
            src_ip_str = socket.inet_ntop(socket.AF_INET6, src_ip)
            dest_ip_str = socket.inet_ntop(socket.AF_INET6, dest_ip)
            
            traffic_class_bin = f"{traffic_class:08b}"
            priority_bits = traffic_class_bin[:3]
            delay_bit, throughput_bit, reliability_bit = traffic_class_bin[3], traffic_class_bin[4], traffic_class_bin[5]
            unused_bits = traffic_class_bin[6:]
            
            priority_map = {
                "000": "De rutina", "001": "Prioritario", "010": "Inmediato",
                "011": "Relámpago", "100": "Invalidación relámpago",
                "101": "Procesando llamada crítica y de emergencia",
                "110": "Control de trabajo de Internet", "111": "Control de red"
            }
            priority = priority_map.get(priority_bits, "Desconocido")
            delay = "Bajo" if delay_bit == "1" else "Normal"
            throughput = "Alto" if throughput_bit == "1" else "Normal"
            reliability = "Alta" if reliability_bit == "1" else "Normal"
            
            next_header_map = {
                1: "ICMPv4", 6: "TCP", 17: "UDP", 58: "ICMPv6",
                118: "STP", 121: "SMP"
            }
            next_header_str = next_header_map.get(next_header, f"Desconocido ({next_header})")
            
            print("\n-------------------------- IPv6 Header --------------------------")
            print(f"Versión:          {version}")
            print(f"Traffic Class: {traffic_class} (Binario: {traffic_class_bin})")
            print(f"  - Prioridad:    {priority_bits} ({priority})")
            print(f"  - Retardo:      {delay_bit} ({delay})")
            print(f"  - Rendimiento:  {throughput_bit} ({throughput})")
            print(f"  - Fiabilidad:   {reliability_bit} ({reliability})")
            print(f"  - No usados:    {unused_bits} (Reservados)")
            print(f"Flow Label: {flow_label}")
            print(f"Payload Lenght: {payload_length} bytes")
            print(f"Next Header: {next_header} ({next_header_str})")
            print(f"Hop Limit: {hop_limit}")
            print(f"Src IP Address: {compress_ipv6_address(src_ip_str)}")
            print(f"Dest IP Address: {compress_ipv6_address(dest_ip_str)}")
            print("------------------------------------------------------------------")
    except Exception as e:
        print(f"Error: {e}")

def read_icmpv4_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(34)  # Skip Ethernet (14) + IPv4 (20) headers
            bin_data = data.read(8)

            if len(bin_data) < 8:
                raise ValueError("Archivo demasiado pequeño para contener una cabecera ICMPv4 válida.")

            icmp_type = bin_data[0]
            icmp_code = bin_data[1]
            checksum = int.from_bytes(bin_data[2:4], 'big')
            identifier = int.from_bytes(bin_data[4:6], 'big')
            sequence_number = int.from_bytes(bin_data[6:8], 'big')

            type_messages = {
                0: 'Host confirmation (Echo Reply)',
                3: 'Destination or service unreachable',
                5: 'Route redirection',
                8: 'Echo request',
                11: 'Time exceeded'
            }

            code_messages = {
                0: 'Network unreachable',
                1: 'Host unreachable',
                2: 'Protocol unreachable',
                3: 'Port unreachable'
            }

            icmp_type_str = type_messages.get(icmp_type, 'Otro')
            icmp_code_str = code_messages.get(icmp_code, 'Desconocido')

            print("\n------------------------ ICMPv4 Header ------------------------")
            print(f"Type:              {icmp_type} ({icmp_type_str})")
            print(f"Code:              {icmp_code} ({icmp_code_str})")
            print(f"Checksum:          0x{checksum:04x}")
            print(f"Identifier:        {identifier}")
            print(f"Sequence Number:   {sequence_number}")
            print("-------------------------------------------------------------")

    except Exception as e:
        print(f"Error: {e}")

def read_icmpv6_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(54)  # Skip Ethernet (14) + IPv6 (40) headers
            bin_data = data.read(4)
            if len(bin_data) < 4:
                raise ValueError("Archivo demasiado pequeño para una cabecera ICMPv6 válida.")

            icmp_type, icmp_code, icmp_checksum = struct.unpack("!B B H", bin_data)

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

    except Exception as e:
        print(f"Error: {e}")

def read_arp_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(14)  # Skip Ethernet header
            bin_data = data.read(28)
            if len(bin_data) < 28:
                raise ValueError("Archivo demasiado pequeño para contener una cabecera ARP válida.")

            hardware_type = int.from_bytes(bin_data[0:2], 'big')
            protocol_type = bin_data[2:4]
            protocol_type_str = f"0x{protocol_type.hex()}"

            hardware_size = bin_data[4]
            protocol_size = bin_data[5]

            opcode = int.from_bytes(bin_data[6:8], 'big')

            sender_mac = bin_data[8:14]
            sender_mac_str = ":".join(f"{byte:02x}" for byte in sender_mac)

            sender_ip = bin_data[14:18]
            sender_ip_str = ".".join(map(str, sender_ip))

            target_mac = bin_data[18:24]
            target_mac_str = ":".join(f"{byte:02x}" for byte in target_mac)

            target_ip = bin_data[24:28]
            target_ip_str = ".".join(map(str, target_ip))

            print('\n------- ARP/RARP Header -------')
            print(f"Hardware Type: {hardware_type}")
            print(f"Protocol Type: {protocol_type_str}")
            print(f"Hardware Size: {hardware_size}")
            print(f"Protocol Size: {protocol_size}")
            print(f"Opcode: {opcode}")
            print(f"Sender MAC: {sender_mac_str}")
            print(f"Sender IP: {sender_ip_str}")
            print(f"Target MAC: {target_mac_str}")
            print(f"Target IP: {target_ip_str}")

    except Exception as e:
        print(f"Error: {e}")

def read_tcp_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(34)  # Skip Ethernet (14) + IPv4 (20) headers
            bin_data = data.read(20)

            if len(bin_data) < 20:
                raise ValueError("Archivo demasiado pequeño para contener una cabecera TCP válida.")

            src_port, dest_port, sequence, ack_number, offset_reserved_flags, window, checksum, urgent_pointer = struct.unpack('!HHIIHHHH', bin_data)

            data_offset = (offset_reserved_flags >> 12) * 4

            flags = offset_reserved_flags & 0x01FF
            ns = (flags >> 8) & 1
            cwr = (flags >> 7) & 1
            ece = (flags >> 6) & 1
            urg = (flags >> 5) & 1
            ack = (flags >> 4) & 1
            psh = (flags >> 3) & 1
            rst = (flags >> 2) & 1
            syn = (flags >> 1) & 1
            fin = flags & 1

            print("\n------------------- Transmission Control Protocol -------------------")
            print(f"Puerto de Origen: {src_port}")
            print(f"Puerto de Destino: {dest_port}")
            print(f"N° Secuencia: {sequence}")
            print(f"N° Acuse de recibo: {ack_number}")
            print(f"Longitud de Cabecera: {data_offset} bytes")
            print("Reservado: 000 Not Set")
            print("Banderas TCP:")
            print(f"  NS:  {ns} {'Set' if ns else 'Not set'}")
            print(f"  CWR: {cwr} {'Set' if cwr else 'Not set'}")
            print(f"  ECE: {ece} {'Set' if ece else 'Not set'}")
            print(f"  URG: {urg} {'Set' if urg else 'Not set'}")
            print(f"  ACK: {ack} {'Set' if ack else 'Not set'}")
            print(f"  PSH: {psh} {'Set' if psh else 'Not set'}")
            print(f"  RST: {rst} {'Set' if rst else 'Not set'}")
            print(f"  SYN: {syn} {'Set' if syn else 'Not set'}")
            print(f"  FIN: {fin} {'Set' if fin else 'Not set'}")
            print(f"Tamaño Ventana de Recepción: {window}")
            print(f"Suma de Verificación: 0x{checksum:04x} ({checksum})")
            print(f"Puntero Urgente: {urgent_pointer}")
            
            payload = data.read()
            payload_hex = " ".join(f"{byte:02x}" for byte in payload[:24])
            print(f"TCP payload ({len(payload)} byte(s)):")
            print(f"Datos: {payload_hex}")

    except Exception as e:
        print(f"Error: {e}")

def read_udp_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(34)  # Skip Ethernet and IPv4 headers
            bin_data = data.read(8)

            if len(bin_data) < 8:
                raise ValueError("Archivo demasiado pequeño para ser una cabecera UDP válida.")

            src_port, dest_port, length, checksum = struct.unpack('!HHHH', bin_data)

            print("\n------------------- UDP Header -------------------")
            print(f"Puerto de Origen: {src_port}")
            print(f"Puerto de Destino: {dest_port}")
            print(f"Longitud: {length} bytes")
            print(f"Suma de Verificación: 0x{checksum:04x} ({checksum})")
            
            if dest_port == 53 or src_port == 53:
                return 42  # Return offset for DNS parsing
            return None

    except Exception as e:
        print(f"Error: {e}")

def parse_dns_name(data, offset):
    """Parse DNS name with support for name compression"""
    name_parts = []
    next_offset = offset
    max_jumps = 10  # Prevent infinite loops with compression pointers
    jumps = 0
    final_offset = next_offset  # Initialize final_offset
    
    while True:
        if jumps > max_jumps:
            raise Exception("Too many compression pointers")
            
        if next_offset >= len(data):
            raise Exception("Malformed DNS name (went beyond packet end)")
            
        length = data[next_offset]
        
        # End of name
        if length == 0:
            if jumps == 0:
                final_offset = next_offset + 1
            break
            
        # Handle name compression
        if length & 0xC0 == 0xC0:
            if jumps == 0:
                final_offset = next_offset + 2
            
            pointer = ((length & 0x3F) << 8) | data[next_offset + 1]
            if pointer >= len(data):
                raise Exception("Invalid compression pointer")
            next_offset = pointer
            jumps += 1
            continue
            
        next_offset += 1
        if next_offset + length > len(data):
            raise Exception("Malformed DNS name (label goes beyond packet end)")
            
        try:
            name_parts.append(data[next_offset:next_offset + length].decode('ascii'))
            next_offset += length
            if jumps == 0:
                final_offset = next_offset
        except UnicodeDecodeError:
            raise Exception("Invalid characters in DNS name")
    
    return name_parts, final_offset

def read_dns_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            udp_result = read_udp_header(file)
            if udp_result is None:
                print("Error: Not a DNS packet (UDP port != 53)")
                return
            
            data.seek(udp_result)  # Seek to DNS header start
            dns_data = data.read()  # Read remaining data for DNS parsing
            
            if len(dns_data) < 12:  # Minimum DNS header size
                raise ValueError("Archivo demasiado pequeño para contener una cabecera DNS válida.")
            
            # Parse DNS header fields
            transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', dns_data[:12])
            
            # Parse DNS flags
            qr = (flags >> 15) & 0x1
            opcode = (flags >> 11) & 0xF
            aa = (flags >> 10) & 0x1
            tc = (flags >> 9) & 0x1
            rd = (flags >> 8) & 0x1
            ra = (flags >> 7) & 0x1
            z = (flags >> 4) & 0x7
            rcode = flags & 0xF
            
            opcode_types = {
                0: "QUERY", 1: "IQUERY", 2: "STATUS"
            }
            
            rcode_types = {
                0: "No error", 1: "Format error",
                2: "Server failure", 3: "Name Error",
                4: "Not Implemented", 5: "Refused"
            }
            
            dns_types = {
                1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
                12: "PTR", 13: "HINFO", 15: "MX", 28: "AAAA"
            }
            
            print("\n-------------------------- DNS Header --------------------------")
            print(f"Transaction ID: 0x{transaction_id:04x}")
            print(f"Flags: 0x{flags:04x}")
            print(f"  QR: {qr} ({'Response' if qr else 'Query'})")
            print(f"  Opcode: {opcode} ({opcode_types.get(opcode, 'Unknown')})")
            print(f"  AA: {aa} ({'Set' if aa else 'Not set'})")
            print(f"  TC: {tc} ({'Set' if tc else 'Not set'})")
            print(f"  RD: {rd} ({'Set' if rd else 'Not set'})")
            print(f"  RA: {ra} ({'Set' if ra else 'Not set'})")
            print(f"  Z: {z} (Reserved)")
            print(f"  RCODE: {rcode} ({rcode_types.get(rcode, 'Unknown')})")
            print(f"Questions: {qdcount}")
            print(f"Answer RRs: {ancount}")
            print(f"Authority RRs: {nscount}")
            print(f"Additional RRs: {arcount}")
            
            current_offset = 12  # Start after header
            
            print("\nQuestions Section:")
            for i in range(qdcount):
                try:
                    qname_parts, new_offset = parse_dns_name(dns_data, current_offset)
                    current_offset = new_offset
                    
                    if current_offset + 4 > len(dns_data):
                        raise ValueError("Malformed DNS packet - incomplete question section")
                    
                    qtype, qclass = struct.unpack('!HH', dns_data[current_offset:current_offset + 4])
                    current_offset += 4
                    
                    name = '.'.join(qname_parts)
                    if name and not name.endswith('.'):
                        name += '.'
                    
                    print(f"\nQuestion {i + 1}:")
                    print(f"  Name: {name}")
                    print(f"  Type: {dns_types.get(qtype, f'TYPE{qtype}')} ({qtype})")
                    print(f"  Class: {'IN' if qclass == 1 else f'CLASS{qclass}'} ({qclass})")
                except Exception as e:
                    print(f"Error parsing question {i + 1}: {e}")
                    break
            
            print("\nAnswers Section:")
            for i in range(ancount):
                try:
                    name_parts, new_offset = parse_dns_name(dns_data, current_offset)
                    current_offset = new_offset
                    
                    if current_offset + 10 > len(dns_data):
                        raise ValueError("Malformed DNS packet - incomplete answer section")
                    
                    atype, aclass, ttl, rdlength = struct.unpack('!HHIH', dns_data[current_offset:current_offset + 10])
                    current_offset += 10
                    
                    print(f"\nAnswer {i + 1}:")
                    print(f"  Name: {'.'.join(name_parts)}")
                    print(f"  Type: {dns_types.get(atype, f'Unknown ({atype})')}")
                    print(f"  Class: {'IN' if aclass == 1 else aclass}")
                    print(f"  TTL: {ttl} seconds")
                    print(f"  Data Length: {rdlength} bytes")
                    
                    # Check if the RDATA length itself would exceed the packet boundary
                    if current_offset + rdlength > len(dns_data):
                        raise ValueError(f"RDATA length ({rdlength}) invalid for remaining packet size ({len(dns_data) - current_offset})")
                    
                    if atype == 1 and rdlength == 4:  # A Record (IPv4)
                        ip = dns_data[current_offset:current_offset + 4]
                        print(f"  Address: {'.'.join(map(str, ip))}")
                    elif atype in [2, 5, 12]:  # NS, CNAME, PTR
                        rdata_parts, _ = parse_dns_name(dns_data, current_offset)
                        print(f"  Target: {'.'.join(rdata_parts)}")
                    elif atype == 15 and rdlength > 2:  # MX
                        preference = struct.unpack('!H', dns_data[current_offset:current_offset + 2])[0]
                        exchange_parts, _ = parse_dns_name(dns_data, current_offset + 2)
                        print(f"  Preference: {preference}")
                        print(f"  Exchange: {'.'.join(exchange_parts)}")
                    
                    current_offset += rdlength
                except Exception as e:
                    print(f"Error parsing answer {i + 1}: {e}")
                    break # Stop processing further answers on error
            
            print("\n---------------------------------------------------------------")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Example usage
    test_ipv4_file = "ethernet_ipv4_udp_dns.bin"
    test_ipv6_file = "ipv6_nd_adv_1.bin"
    
    print("\n=== Testing IPv4 Packet Analysis ===")
    read_ethernet_header(test_ipv4_file)
    read_ipv4_header(test_ipv4_file)
    read_udp_header(test_ipv4_file)
    read_dns_header(test_ipv4_file)
    
    print("\n=== Testing IPv6 Packet Analysis ===")
    read_ethernet_header(test_ipv6_file)
    read_ipv6_header(test_ipv6_file)
    read_icmpv6_header(test_ipv6_file)