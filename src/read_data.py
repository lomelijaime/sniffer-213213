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
            print('\n--- Cabecera Ethernet ---')
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
            data.seek(14) #Salta la trama ethernet
            bin_data = data.read(20)  # Leer la cabecera mínima IPv4
            if len(bin_data) < 20:
                print("Error: Archivo demasiado pequeño para contener una cabecera IPv4 válida.")
                return
            
            # Desempaquetar la cabecera IPv4
            version_ihl, tos, total_length, identification, flags_frag_offset, ttl, protocol, checksum, src_ip, dest_ip = struct.unpack("!BBHHHBBHII", bin_data)

            version = version_ihl >> 4  # Extraer la versión
            ihl = (version_ihl & 0x0F) * 4

            # Convertir direcciones IP a formato legible
            src_ip_str = ".".join(map(str, src_ip.to_bytes(4, 'big')))  # Direccion de origen
            dest_ip_str = ".".join(map(str, dest_ip.to_bytes(4, 'big'))) # Direccion de destino

            #--Impresión de cabeceras
            print("\n--- Cabecera IPv4 ---")
            print(f"Versión: {version}")
            print(f"Longitud de la Cabecera (IHL): {ihl} bytes")
            print(f"Protocolo: {protocol}") 
            print(f"Dirección IP de Origen: {src_ip_str}")  
            print(f"Dirección IP de Destino: {dest_ip_str}") 

            # Leer opciones y relleno si IHL > 20 
            # ---Mensaje de Jaime, por favor pasarme la IHL (Longitud de cabecera o Internet Header Length) con esa variable para poder leer y mostrar opciones y relleno en caso de que existan
            if ihl > 20:
                options_size = ihl - 20  # Tamaño de las opciones y relleno
                options_padding = data.read(options_size)  # Leer bytes extra
                options_hex = options_padding.hex()

                print(f"Opciones y Relleno: {options_hex}")
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{file}' en la carpeta data/")
    except Exception as e:
        print(f"Error inesperado: {e}")


read_ethernet_header("ethernet_ipv4_icmp_ping_2.bin")
read_ipv4_header("ethernet_ipv4_icmp_ping_2.bin")