# Mejoras en la lectura de la cabecera Ethernet:
# - Muestra MAC destino, MAC origen y Ethertype.
# - Formatea direcciones MAC correctamente.
# - Manejo de errores para archivos inexistentes o corruptos.

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

            print(f"MAC Destino: {dest_mac_str}")
            print(f"MAC Origen: {src_mac_str}")
            print(f"Ethertype: {ethertype_str}")

    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{file}' en la carpeta data/")
    except Exception as e:
        print(f"Error inesperado: {e}")

read_ethernet_header("ethernet_1.bin")