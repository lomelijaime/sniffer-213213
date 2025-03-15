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

def read_ipv6_header(file):
    try:
        filepath = os.path.join("data", file)
        with open(filepath, 'rb') as data:
            data.seek(14)  # Saltar la cabecera Ethernet
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
            
            # Mapeo de protocolos para el campo "Encabezado siguiente"
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


# Llamadas a las funciones para probar
read_ethernet_header("ipv6_nd_adv_1.bin")
read_ipv6_header("ipv6_nd_adv_1.bin")