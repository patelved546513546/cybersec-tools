from scapy.all import rdpcap
import pandas as pd
packets=rdpcap("day.pcapng")
data=[]
for pkt in packets:
	if pkt.haslayer("IP"):
		length=len(pkt)
		proto=pkt.payload.proto
		src=pkt.payload.src
		dst=pkt.payload.dst
		data.append([src,dst,proto,length])

df=pd.DataFrame(data,columns=["src_ip","dst_ip","protocol","length"])
df.to_csv("packet_features.csv", index=False)
print("[+] Features saved to packet_features.csv")


