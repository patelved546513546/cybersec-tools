from scapy.all import rdpcap, TCP

pcap_file = 'telnet_login.pcap'

packets = rdpcap(pcap_file)

for packet in packets:
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        if dport == 23 or dport == 21:  # Telnet: 23, FTP: 21
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.decode(errors='ignore')
                if any(keyword in payload.lower() for keyword in ['login', 'user', 'pass']):
                    print(f"[+] Found possible credential data: {payload.strip()}")
