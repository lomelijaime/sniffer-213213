def bin_to_txt(bin_file, txt_file, mode='hex'):
    """
    Convierte un archivo binario a un archivo de texto.
    
    :param bin_file: Ruta del archivo binario de entrada.
    :param txt_file: Ruta del archivo de texto de salida.
    :param mode: Modo de conversión ('hex' para hexadecimal, 'ascii' para ASCII si es posible).
    """
    try:
        with open(bin_file, 'rb') as bin_f, open(txt_file, 'w', encoding='utf-8') as txt_f:
            data = bin_f.read()
            
            if mode == 'hex':
                txt_f.write(data.hex())  # Escribe en formato hexadecimal
            elif mode == 'ascii':
                try:
                    txt_f.write(data.decode('utf-8'))  # Intenta escribir en formato ASCII
                except UnicodeDecodeError:
                    print("El archivo no puede representarse completamente en ASCII.")
                    txt_f.write(data.hex())  # Como alternativa, usa hexadecimal
            else:
                print("Modo no soportado. Use 'hex' o 'ascii'.")
    
        print(f"Conversión completada. Archivo guardado en: {txt_file}")
    
    except FileNotFoundError:
        print("Error: Archivo binario no encontrado.")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Ejemplo de uso
bin_to_txt('D:\Sniffer-Beatriz\sniffer-213213\data\ipv6_icmpv6_destination_unreachable.bin', 'salida.txt', mode='hex')
