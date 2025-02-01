def read_ethernet_header(file):
    data = open(f"data/{file}", 'rb')
    try:
        bin = data.read(14)
        
    finally:
        data.close()
    # Split those 14 bytes
    dest_mac = bin[0:6]
    src_mac = bin[6:12]
    ethertype = bin[12:14]
    
    show_dest = [f"{byte:02x}" for byte in dest_mac]
    print(show_dest)
read_ethernet_header("ethernet_1.bin")