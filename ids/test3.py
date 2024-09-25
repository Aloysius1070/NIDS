import PySimpleGUI as sg
import scapy.all as scp
import scapy.arch.windows as scpwinarch
import threading
import socket

sg.theme("BluePurple")


def readrules():
    rulefile="rules.txt"
    ruleslist=[]
    with open(rulefile,"r") as rf:
        ruleslist=rf.readlines()
    rules_list=[]
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list

alertprotocols=[]
alertdestips=[]
alertsrcips=[]
alertsrcports=[]
alertdestports=[]
alertmsg=[]

def process_rules(rulelist):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsg

    alertprotocols=[]
    alertdestips=[]
    alertsrcips=[]
    alertsrcports=[]
    alertdestports=[]
    alertmsg=[]



    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")
        if rulewords[2] != "any":
            srcip = rulewords[2]
            alertsrcips.append(srcip.lower())
        else:
            alertsrcips.append("any")
        if rulewords[3] != "any":
            srcport = int(rulewords[3])
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")
        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")
        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")
        try:
            alertmsg.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))
        except:
            alertmsg.append("")
            pass    

    print(alertprotocols)
    print(alertdestips)
    print(alertsrcips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsg)

process_rules(readrules())


source_ip_counts = {}

# def count_source_ips(packets):
#         # source_ip_counts = {}
#         for pkt in packets:
#             src_ip = pkt["IP"].src
#             if src_ip in source_ip_counts:
#                 source_ip_counts[src_ip] += 1
#             else:
#                 source_ip_counts[src_ip] = 1
#         return source_ip_counts
# source_ip_counts = count_source_ips(pkt_process())

# # Print the results
# for src_ip, count in source_ip_counts.items():
#     print(f"Source IP: {src_ip}, Count: {count}")





suspiciouspackets=[]
sus_packetactual=[]
sus_readablepayloads=[]

pktsummarylist=[]
updatepktlist=False


def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def check_rules_warning(pkt):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsg
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()  
            sport =pkt['IP'].sport
            dport = pkt['IP'].dport

            for i in range(len(alertprotocols)):
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i] 
                else:
                    chkproto = proto
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest
                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src
                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport


                if (str(src).strip()==str(chksrcip).strip() and
                    str(dest).strip()==str(chkdestip).strip() and
                    str(proto).strip()==str(chkproto).strip() and
                    str(dport).strip()==str(chkdestport).strip() and
                    str(sport).strip()==str(chksrcport).strip()):
                    
                    print("Flagged Packets")


                    if proto=="tcp":
                        try:
                            print(pkt["TCP"])
                            readable_payload=bytes(pkt['TCP']).decode("UTF-8","replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex: 
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto=="udp":
                        try:
                            readable_payload=bytes(pkt['UDP'].payload).decode("UTF-8","replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting udp payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("not tcp or udp")
                    return True,str(alertmsg[i])
        except:
            pkt.show()
    
    return False,""

# layout=[[
#     sg.Button("STARTCAP",key='-startcap-'), 
#     sg.Button("STOPCAP",key='-stopcap-'),
#     sg.Button("SAVECAP",key='-savecap-'),
#     sg.Button("REFRESH RULES",key='-refreshrules-'),],
#     [sg.Text("ALL PACKETS",font=('Arial bold',20))],
#     [sg.Listbox(key='-pktsall-',
#                 size=(100,20),
#                 enable_events=True,
#                 values=pktsummarylist),
#     sg.Listbox(key='-pkts-',
#                 size=(100,20),
#                 enable_events=True,
#                 values=suspiciouspackets)]
#     ]

# window=sg.Window("main window",layout,size=(1600,800),resizable=True)

pkt_list=[]

ifaces=[str(x['name']) for x in scpwinarch.get_windows_if_list()]
capiface=ifaces[0]

def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    pkt_summary=pkt.summary()
    pktsummarylist.append(pkt_summary)
    pkt_list.append(pkt)

    sus_pkt,sus_msg=check_rules_warning(pkt)
    if sus_pkt==True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist)-1} {pkt_summary} MSG:{sus_msg}")
        sus_packetactual.append(pkt)
    return




sniffthread=threading.Thread(target=scp.sniff,
                             kwargs={
                                 "prn":pkt_process,
                                 'filter':"",},
                                 daemon=True
                             )

sniffthread.start()



def count_source_ips(packets):
        # source_ip_counts = {}
        for pkt in packets:
            src_ip = pkt["IP"].src
            if src_ip in source_ip_counts:
                source_ip_counts[src_ip] += 1
            else:
                source_ip_counts[src_ip] = 1
        return source_ip_counts

source_ip_counts = count_source_ips(pkt_process(sniffthread))

# Print the results
for src_ip, count in source_ip_counts.items():
    print(f"Source IP: {src_ip}, Count: {count}")




layout=[[
    sg.Button("STARTCAP",key='-startcap-'), 
    sg.Button("STOPCAP",key='-stopcap-'),
    sg.Button("SAVECAP",key='-savecap-'),
    sg.Button("REFRESH RULES",key='-refreshrules-'),
    sg.Button("givcount",key='-count-'),],
    [sg.Text("ALL PACKETS",font=('Arial bold',20))],
    [sg.Listbox(key='-pktsall-',
                size=(100,20),
                enable_events=True,
                values=pktsummarylist),
    sg.Listbox(key='-pkts-',
                size=(100,20),
                enable_events=True,
                values=suspiciouspackets)],
    sg.Listbox(key='-count-',
                size=(100,20),
                enable_events=True,
                values=source_ip_counts)
    ]

window=sg.Window("main window",layout,size=(1600,800),resizable=True)

while True:
    event,values=window.read()
    if event=='-refreshrules-':
        process_rules(readrules())
    
    if event=='-givcount-':
        count_source_ips(sniffthread)

    if event=='-startcap-':
        updatepktlist=True
        pktsummarylist=[]
        pkt_list=[]

        while True:
            event,values=window.read(timeout=10)
            if event=='-refreshrules-':
                process_rules(readrules())
            if event=='-stopcap-':
                updatepktlist=False
                break

            if event == sg.TIMEOUT_EVENT:
                 window["-pktsall-"].update(values=pktsummarylist, scroll_to_index=len(pktsummarylist))
                 window["-pkts-"].update(values=suspiciouspackets, scroll_to_index=len(suspiciouspackets))



