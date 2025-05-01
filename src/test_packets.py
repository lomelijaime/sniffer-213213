from read_data import *

def test_ethernet_ipv4_dns():
    print("\n=== Testing Full IPv4 DNS Packet Analysis ===")
    dns_file = "ethernet_ipv4_udp_dns.bin"
    read_ethernet_header(dns_file)  # Ethernet
    read_ipv4_header(dns_file)     # IPv4
    read_udp_header(dns_file)      # UDP
    read_dns_header(dns_file)      # DNS

def test_ipv6_icmpv6():
    print("\n=== Testing Full IPv6 ICMPv6 Packet Analysis ===")
    ipv6_file = "ipv6_nd_adv_1.bin"
    read_ethernet_header(ipv6_file)  # Ethernet
    read_ipv6_header(ipv6_file)      # IPv6
    read_icmpv6_header(ipv6_file)    # ICMPv6

def test_ipv4_icmp():
    print("\n=== Testing IPv4 ICMP Packet Analysis ===")
    icmp_file = "ethernet_ipv4_icmp_ping.bin"
    read_ethernet_header(icmp_file)  # Ethernet
    read_ipv4_header(icmp_file)      # IPv4
    read_icmpv4_header(icmp_file)    # ICMPv4

def test_ipv4_tcp():
    print("\n=== Testing IPv4 TCP Packet Analysis ===")
    tcp_file = "ethernet_ipv4_tcp_syn.bin"
    read_ethernet_header(tcp_file)  # Ethernet
    read_ipv4_header(tcp_file)      # IPv4
    read_tcp_header(tcp_file)       # TCP with SYN flag

def test_arp():
    print("\n=== Testing ARP Packet Analysis ===")
    arp_file = "ethernet_arp_request.bin"
    read_ethernet_header(arp_file)  # Ethernet
    read_arp_header(arp_file)       # ARP Request

def test_ipv4_dns_query():
    print("\n=== Testing DNS Query Packet Analysis ===")
    dns_query_file = "ethernet_ipv4_udp_dns_1.bin"
    read_ethernet_header(dns_query_file)  # Ethernet
    read_ipv4_header(dns_query_file)      # IPv4
    read_udp_header(dns_query_file)       # UDP
    read_dns_header(dns_query_file)       # DNS Query

def test_icmp_types():
    print("\n=== Testing Different ICMP Types ===")
    # Echo Request (Ping)
    print("\n--- Testing ICMP Echo Request ---")
    ping_file = "ethernet_ipv4_icmp_ping.bin"
    read_ethernet_header(ping_file)
    read_ipv4_header(ping_file)
    read_icmpv4_header(ping_file)

    # Echo Reply (Pong)
    print("\n--- Testing ICMP Echo Reply ---")
    pong_file = "ethernet_ipv4_icmp_pong.bin"
    read_ethernet_header(pong_file)
    read_ipv4_header(pong_file)
    read_icmpv4_header(pong_file)

    # Destination Unreachable
    print("\n--- Testing ICMP Destination Unreachable ---")
    unreach_file = "ethernet_ipv4_icmp_host_unreachable.bin"
    read_ethernet_header(unreach_file)
    read_ipv4_header(unreach_file)
    read_icmpv4_header(unreach_file)

def test_ipv6_types():
    print("\n=== Testing Different IPv6 Packet Types ===")
    # ICMPv6 Echo Request
    print("\n--- Testing ICMPv6 Echo Request ---")
    ping6_file = "ipv6_icmpv6_ping.bin"
    read_ethernet_header(ping6_file)
    read_ipv6_header(ping6_file)
    read_icmpv6_header(ping6_file)

    # ICMPv6 Echo Reply
    print("\n--- Testing ICMPv6 Echo Reply ---")
    pong6_file = "ipv6_icmpv6_pong.bin"
    read_ethernet_header(pong6_file)
    read_ipv6_header(pong6_file)
    read_icmpv6_header(pong6_file)

    # Neighbor Discovery
    print("\n--- Testing IPv6 Neighbor Discovery ---")
    nd_file = "ipv6_nd_sol_1.bin"
    read_ethernet_header(nd_file)
    read_ipv6_header(nd_file)
    read_icmpv6_header(nd_file)

if __name__ == "__main__":
    print("Starting comprehensive packet analysis tests...")
    
    test_ethernet_ipv4_dns()    # Full IPv4 DNS packet
    #test_ipv6_icmpv6()          # Full IPv6 ICMPv6 packet
    #test_ipv4_icmp()            # IPv4 ICMP packet
    #test_ipv4_tcp()             # IPv4 TCP packet
    #test_arp()                  # ARP packet
    #test_ipv4_dns_query()       # DNS Query packet
    #test_icmp_types()           # Various ICMP types
    #test_ipv6_types()           # Various IPv6 packet types
    
    print("\nAll packet analysis tests completed.")