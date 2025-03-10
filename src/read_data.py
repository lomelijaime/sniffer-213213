import struct


def read_ethernet_header(file):
    try:
        with open(f"data/{file}", 'rb') as data:
            bin_data = data.read(14)
            if len(bin_data) < 14:
                print("Error: Archivo demasiado pequeño para ser una trama Ethernet válida.")
                return

            dest_mac = bin_data[0:6]
            src_mac = bin_data[6:12]
            ethertype = bin_data[12:14]

            # Convertir a formato legible
            dest_mac_str = ":".join(f"{byte:02x}" for byte in dest_mac)
            src_mac_str = ":".join(f"{byte:02x}" for byte in src_mac)
            ethertype_str = f"0x{ethertype.hex()}"
            print('\n------- Ethernet Header -------')
            print(f"MAC Destino: {dest_mac_str}")
            print(f"MAC Origen: {src_mac_str}")
            print(f"Ethertype: {ethertype_str}")

    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{file}' en la carpeta data/")
    except Exception as e:
        print(f"Error inesperado: {e}")


def read_ipv4_header(file):
    try:
        with open(f"data/{file}", 'rb') as data:
            data.seek(14)  # Salta la trama ethernet
            bin_data = data.read(20)  # Leer la cabecera mínima IPv4
            if len(bin_data) < 20:
                print("Error: Archivo demasiado pequeño para contener una cabecera IPv4 válida.")
                return

            # Desempaquetar la cabecera IPv4
            version_ihl, tos, total_length, identification, flags_frag_offset, ttl, protocol, checksum, src_ip, dest_ip = struct.unpack(
                "!BBHHHBBHII", bin_data)

            version = version_ihl >> 4  # Extraer la versión
            ihl = (version_ihl & 0x0F) * 4  # Calcular IHL en bytes

            # Extraer Flags y Desplazamiento de Fragmento
            flags = (flags_frag_offset >> 13) & 0b111  # Tomar los 3 bits más significativos
            fragment_offset = flags_frag_offset & 0x1FFF  # Tomar los últimos 13 bits

            # Separar los bits de las flags
            reserved_flag = (flags >> 2) & 0x1  # Bit reservado
            df_flag = (flags >> 1) & 0x1  # Don't Fragment (DF)
            mf_flag = flags & 0x1  # More Fragments (MF)

            # Convertir direcciones IP a formato legible
            src_ip_str = ".".join(map(str, src_ip.to_bytes(4, 'big')))  # Dirección de origen
            dest_ip_str = ".".join(map(str, dest_ip.to_bytes(4, 'big')))  # Dirección de destino

            # Convertir valores a binario para visualización
            identification_bin = format(identification, '016b')
            flags_bin = format(flags, '03b')
            fragment_offset_bin = format(fragment_offset, '013b')
            checksum_bin = format(checksum, '016b')

            # Imprimir salida con formato detallado
            print("\n-------------------------- IPV4 Header --------------------------")
            print(f"Version:           {version}")
            print(f"IHL:               {ihl // 4} ({ihl} bytes)")
            print(f"TOS:               {format(tos, '08b')}")
            print(f"                   Precedence (000):              Routine")
            print(
                f"                   Delay (Bit 3: {tos >> 3 & 0x1}):         {'Low' if tos >> 3 & 0x1 else 'Normal'}")
            print(
                f"                   Throughput (Bit 4: {tos >> 4 & 0x1}):    {'High' if tos >> 4 & 0x1 else 'Normal'}")
            print(
                f"                   Reliability (Bit 5: {tos >> 5 & 0x1}):   {'High' if tos >> 5 & 0x1 else 'Normal'}")
            print(f"                   Reserved (Bits 6-7: {format(tos >> 6, '02b')})")
            print(f"Total Length:      {total_length} bytes")
            print(f"Identification:    {identification_bin}")
            print(f"Flags:             {flags_bin} ", end="")

            # Explicación de las flags
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

    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{file}' en la carpeta data/")
    except Exception as e:
        print(f"Error inesperado: {e}")


def read_icmpv4_header(file):
    try:
        with open(f"data/{file}", 'rb') as data:
            data.seek(34)  # Saltar la cabecera Ethernet (14 bytes) + IPv4 (20 bytes)
            bin_data = data.read(8)  # Leer los primeros 8 bytes de la cabecera ICMP

            if len(bin_data) < 8:
                print("Error: Archivo demasiado pequeño para contener una cabecera ICMPv4 válida.")
                return

            # Extraer los campos de la cabecera ICMP
            icmp_type = bin_data[0]
            icmp_code = bin_data[1]
            checksum = int.from_bytes(bin_data[2:4], 'big')
            identifier = int.from_bytes(bin_data[4:6], 'big')
            sequence_number = int.from_bytes(bin_data[6:8], 'big')

            # Mapear tipos de ICMP
            type_messages = {
                0: 'Host confirmation (Echo Reply)',
                3: 'Destination or service unreachable',
                5: 'Route redirection',
                8: 'Echo request',
                11: 'Time exceeded'
            }

            # Mapear códigos de ICMP
            code_messages = {
                0: 'Network unreachable',
                1: 'Host unreachable',
                2: 'Protocol unreachable',
                3: 'Port unreachable'
            }

            icmp_type_str = type_messages.get(icmp_type, 'Otro')
            icmp_code_str = code_messages.get(icmp_code, 'Desconocido')

            # Imprimir la cabecera ICMPv4
            print("\n------------------------ ICMPv4 Header ------------------------")
            print(f"Type:              {icmp_type} ({icmp_type_str})")
            print(f"Code:              {icmp_code} ({icmp_code_str})")
            print(f"Checksum:          0x{checksum:04x}")
            print(f"Identifier:        {identifier}")
            print(f"Sequence Number:   {sequence_number}")
            print("-------------------------------------------------------------")

    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{file}' en la carpeta data/")
    except Exception as e:
        print(f"Error inesperado: {e}")


def read_arp_header(file):
    try:
        with open(f"data/{file}", 'rb') as data:
            bin_data = data.read(28)
            if len(bin_data) < 28:
                print("Error: Archivo demasiado pequeño para contener una cabecera ARP válida.")
                return

            hardware_type = int.from_bytes(bin_data[0:2], 'big')  # working
            protocol_type = bin_data[2:4]
            protocol_type_str = f"0x{protocol_type.hex()}"

            hardware_size = bin_data[4]
            protocol_size = bin_data[5]

            opcode = int.from_bytes(bin_data[6:8], 'big')  # working

            sender_mac = bin_data[8:14]
            sender_mac_str = ":".join(f"{byte:02x}" for byte in sender_mac)  # working

            sender_ip = bin_data[14:18]
            sender_ip_str = ".".join(map(str, sender_ip))  # working

            target_mac = bin_data[18:24]
            target_mac_str = ":".join(f"{byte:02x}" for byte in target_mac)  # working

            target_ip = bin_data[24:28]
            target_ip_str = ".".join(map(str, target_ip))  # working

            # Imprimir cabezera ARP/RARP
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




    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{file}' en la carpeta data/")
    except Exception as e:
        print(f"Error inesperado: {e}")


# Llamadas a las funciones para probar
read_ethernet_header("ethernet_ipv4_icmp_ping.bin")
read_ipv4_header("ethernet_ipv4_icmp_ping.bin")
read_icmpv4_header("ethernet_ipv4_icmp_ping.bin")
read_arp_header("ethernet_arp_reply.bin")
read_arp_header("ethernet_arp_request.bin")
