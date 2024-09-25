import scapy.all as scp

pkt=scp.sniff(count=2)
def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    pkt_summary=pkt.summary()
    print(pkt_summary)
    return
pkt_process(pkt)
for i in pkt:
    packets=str(i).split(" ")
    print(packets)
    print(i['IP'].src,i['IP'].dst,i['IP'].ttl)