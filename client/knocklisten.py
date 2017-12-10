#!/usr/bin/env python
from scapy.all import *
from IptableManager import IptableManager
from dcaes import AESCipher

class KnockListener(object):
    def __init__(self):
        self.port_list = [8000, 9000, 7000]
        self.incoming_ips = {}
        self.iptable_manager = IptableManager()
        self.aes_cipher = AESCipher()

    def listen(self):
        print('Listening...')
        sniff(filter='udp', prn=self.handle_packets)

    def handle_packets(self, pkt):
        port_num = pkt[UDP].dport
        src_ip = pkt[IP].src

        # if the packet is going to a port that's not in the list, ignore it
        if port_num not in self.port_list:
            # also, delete any entries for the incoming ip address
            if src_ip in self.incoming_ips:
                self.incoming_ips.pop(src_ip)
            return

        # if the ip isnt already in the map, either add it if it got the first
        # knock correct, or do nothing. Either way, return afterwards
        if src_ip not in self.incoming_ips:
            if port_num == self.port_list[0]:
                print('Added ' + src_ip + ' to list')
                self.incoming_ips[src_ip] = [port_num]
                print(src_ip + ': ' + str(self.incoming_ips[src_ip]))
            return

        # if we've made it this far, we know the incoming ip is in the map already

        # the length of the key list should also be the index of the next item
        # in the port list sequence
        list_length = len(self.incoming_ips[src_ip])
        # if the next item matches the incoming port number, add the port to
        # the list
        if self.port_list[list_length] == port_num:
            self.incoming_ips[src_ip].append(port_num)
            print(src_ip + ': ' + str(self.incoming_ips[src_ip]))
        else:
            # otherwise, the knock was wrong
            print(src_ip + ' reset - bad knock')
            self.incoming_ips.pop(src_ip)
            return

        # if the key list matches the port list sequence, allow the connection
        # from that ip
        if self.incoming_ips[src_ip] == self.port_list:
            print('Knock sequence accepted from ' + src_ip)
            self.incoming_ips.pop(src_ip)
            self.accept_connection(src_ip)


    def accept_connection(self, ip):
        # add an iptables rule to allow a connection from ip
        i = "s"

        self.iptable_manager.manage_port_rules("TCP", ip, "7005", 10, True)

        # Open dummy file to receive data
        received_data = open("encrypted_recv.txt", "wb")

        # New thread to listen on socket and receive file transfer
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_ip = socket.gethostbyname(socket.gethostname())

        tcp_socket.bind(host_ip, ip)

        # write encrypted data to a file
        connection, a = tcp_socket.accept()

        while True:
            data = connection.recv(1024)

            if data.endswith("EOF"):
                data = data[:-3]
                received_data.write(data)
                break

            received_data.write(data)

        received_data.close()

        # Decrypt received data
        self.aes_cipher.decrypt_file("encrypted_recv.txt")



if __name__ == '__main__':
    KnockListener().listen()

