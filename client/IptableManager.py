import os
import time
import thread


class IptableManager(object):
    """
    Handles opening the specified port using IPTABLES firewall rules
    """

    def __init__(self):
        pass

    def manage_port_rules(self, protocol, ip, port, time_to_live, is_threaded):
        """
        Sets a rule in iptables to allow connection to the specified port

        :param protocol: protocol the connection should accept (TCP / UDP)
        :param time_to_live: time to keep the rule alive (0 means keep alive indefinitely)
        :param is_threaded: whether to manage the rule on a separate thread
        """

        if is_threaded:
            thread.start_new_thread(self.open_port, (protocol, ip, port, time_to_live))
        else:
            self.open_port(protocol, ip, port, time_to_live)

    def open_port(self,  protocol, ip, port, time_to_live):
        """
        Creates an acceptance rule for the ip/port/protocol specified. After the duration of time_to_live (seconds)
        the acceptance rules are removed.

        If time_to_live is 0, the rule will not be removed unless a call to close_connection is made using the
        matching ip/protocol/port this call was made with.

        :param protocol:
        :param port:
        :param time_to_live:
        :return:
        """

        self.open_connection(protocol, ip, port)

        # Wait time to live before closing connection
        if time_to_live > 0:
            time.sleep(time_to_live)
            self.close_connection(protocol, ip, port)
            print('rule closed')

    def open_connection(self, protocol, ip, port):
        os.system(self.build_add_input_rule(protocol, ip, port))
        os.system(self.build_add_output_rule(protocol, ip, port))

    def close_connection(self, protocol, ip, port):
        os.system(self.build_remove_input_rule(protocol, ip, port))
        os.system(self.build_remove_output_rule(protocol, ip, port))

    def build_add_input_rule(self, protocol, ip, port):
        return "iptables -A INPUT -p " + protocol + " --dport " + port + " -s " + ip + " -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"

    def build_add_output_rule(self, protocol, ip, port):
        return "iptables -A OUTPUT -p " + protocol + " --sport " + port + " -d " + ip +  " -m conntrack --ctstate ESTABLISHED -j ACCEPT"

    def build_remove_input_rule(self, protocol, ip, port):
        return "iptables -D INPUT -p " + protocol + " --dport " + port + " -s " + ip +  " -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"

    def build_remove_output_rule(self, protocol, ip, port):
        return "iptables -D OUTPUT -p " + protocol + " --sport " + port + " -d " + ip +  " -m conntrack --ctstate ESTABLISHED -j ACCEPT"
