import argparse
import scapy.all as scapy

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="specify an interface to sniff")
    options = parser.parse_args()

    if not options.interface:
        parser.error("You need to specify an interface")

    return options.interface

def sniff_packets(interface):
    packets = scapy.sniff(iface=interface, prn=analyse_packet)
    return packets

def analyse_packet(packet):
    print(packet.summary())

interface = get_interface()
packets = sniff_packets(interface)

# Process the captured packets
for pkt in packets:
    # Your analysis logic here
    print(pkt)