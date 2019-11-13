#!/usr/bin/env python
import scapy.all as scapy
import csv
import ipwhois
import ipaddress

NETFLIX_NET_MASKS_PATH = "./netflix_net_masks.conf"

identified_ipv4 = set()
identified_ipv6 = set()
netflix_domains = set()


def load_stored_net_masks(path):
    with open(path, 'r') as net_mask_file:
        loaded_mask_set = set()
        reader = csv.reader(net_mask_file)
        loaded_mask_list = list(reader)
        for entry in loaded_mask_list:
            ip, bit_mask = entry[0].split('/')
            loaded_mask_set.add((ip, bit_mask))
        return loaded_mask_set


def get_subnet_for_ipv4(ip):
    who_is = ipwhois.IPWhois(ip)
    result = who_is.lookup_rdap()
    print('Address {} belongs to {} with cidr {}.'.format(ip,
                                                          result.get('asn_description'),
                                                          result.get('asn_cidr')))
    subnet, bit_mask = result.get('asn_cidr').split('/')
    return subnet, bit_mask


def check_if_ip_in_stored_sub_nets(ip, sub_nets):
    match_found = False
    for stored_net_mask, stored_bit_mask in sub_nets:
        stored_network = ipaddress.ip_network(stored_net_mask + "/" + stored_bit_mask)
        ip = ipaddress.ip_address(ip)
        if ip in stored_network.hosts():
            print("Match found for stored subnet {}/{}, with ip {}.".format(stored_net_mask, stored_bit_mask, ip))
            match_found = True
    return match_found


def process_sniffed_packet(packet):
    if 'netflix' in str(packet['DNS'].qd[0].qname):
        if packet['DNS'].ancount > 0:
            answer_count = packet['DNS'].ancount
            # print(packet.show())
            for count in range(0, answer_count):
                # Process ipv4 responses
                if packet['DNS'].an[count].type == 1:
                    ip = packet['DNS'].an[count].rdata
                    identified_ipv4.add((packet['DNS'].an[count].rrname, ip))
                # Process ipv6 responses
                elif packet['DNS'].an[count].type == 28:
                    identified_ipv6.add((packet['DNS'].an[count].rrname, packet['DNS'].an[count].rdata))
                # Process CNAME responses
                elif packet['DNS'].an[count].type == 5:
                    print(packet.show())


def write_ips_to_csv(ips, path, filename):
    with open(path + filename, mode='w') as ipfile:
        ip_file_writer = csv.writer(ipfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        for ip in ips:
            ip_file_writer.writerow(ip)


def append_sub_nets_to_file(sub_nets, file_path):
    with open(file_path, mode='a') as file:
        for processed_subnet in sub_nets:
            file.write(processed_subnet + '\n')


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter='udp port 53')


def main():
    netflix_net_masks = load_stored_net_masks(NETFLIX_NET_MASKS_PATH)
    sniff('eth0')
    new_sub_nets = set()
    for url, ip in identified_ipv4:
        print("Process {}.".format(ip))
        match_found = check_if_ip_in_stored_sub_nets(ip, netflix_net_masks)
        if not match_found:
            sub_net, net_mask = get_subnet_for_ipv4(ip)
            new_sub_nets.add(sub_net+"/"+net_mask)

    append_sub_nets_to_file(new_sub_nets, NETFLIX_NET_MASKS_PATH)
    #write_ips_to_csv(identified_ipv4, './', 'test.csv')
    #print(identified_ipv4)
    #print(identified_ipv6)


if __name__ == '__main__':
    main()
