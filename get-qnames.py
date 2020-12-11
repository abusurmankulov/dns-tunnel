import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
types = {0: 'ANY', 255: 'ALL',1: 'A', 2: 'NS', 3: 'MD', 4: 'MD', 5: 'CNAME',
         6: 'SOA', 7:  'MB',8: 'MG',9: 'MR',10: 'NULL',11: 'WKS',12: 'PTR',
         13: 'HINFO',14: 'MINFO',15: 'MX',16: 'TXT',17: 'RP',18: 'AFSDB',
         28: 'AAAA', 33: 'SRV',38: 'A6',39: 'DNAME'}
def get_dns_qnames(src_pcap_name):
    dns_packets = rdpcap(src_pcap_name)
    qnames=[]
    for packet in dns_packets:
        if packet.haslayer(DNS):
            qname=packet[DNS].qd.qname.decode("utf-8")
            qnames.append(qname.rstrip(qname[-1]))
    qnames=list(dict.fromkeys(qnames))
    return(qnames)
def get_src_filenames():
    src_filenames=[]
    for src_filename in os.listdir():
        if src_filename.startswith('snort.log.'):
            src_filenames.append(src_filename)
    return(src_filenames)	
def run_parse():
    for src_filename in get_src_filenames():
        dst_filename=src_filename+'.qname.txt'
        with open(dst_filename, 'w', encoding="utf8") as f:
            for line in get_dns_qnames(src_filename):
                f.write(line + '\n')
    return
