import os
import time
import thread


class RuleManager(object):
    """
    Handles opening the specified port using IPTABLES firewall rules
    """

    def __init__(self):
        python_formatting_is_so_bad = True

    def manage_port_rules(self, protocol, port, time_to_live, is_threaded):
        """
        Sets a rule in iptables to allow connection to the specified port

        :param protocol: protocol the connection should accept (TCP / UDP)
        :param time_to_live: time to keep the rule alive (0 means keep alive indefinitely)
        :param is_threaded: whether to manage the rule on a separate thread
        """

        if is_threaded:
            thread.start_new_thread(self.open_port, (protocol, port, time_to_live))
        else:
            self.open_port(protocol, port, time_to_live)

    def open_port(self,  protocol, port, time_to_live):
        """

        :param protocol:
        :param port:
        :param time_to_live:
        :return:
        """

        self.open_connection(protocol, port)

        # Wait time to live before closing connection
        if time_to_live > 0:
            time.sleep(time_to_live)
            self.close_connection(protocol, port)

    def open_connection(self, protocol, port):
        os.system(self.build_add_input_rule(protocol, port))
        os.system(self.build_add_output_rule(protocol, port))

    def close_connection(self, protocol, port):
        os.system(self.build_remove_input_rule(protocol, port))
        os.system(self.build_remove_output_rule(protocol, port))

    def build_add_input_rule(self, protocol, port):
        return "iptables -A INPUT -p " + protocol + " --dport " + port + " -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"

    def build_add_output_rule(self, protocol, port):
        return "iptables -A OUTPUT -p " + protocol + " --sport " + port + " -m conntrack --ctstate ESTABLISHED -j ACCEPT"

    def build_remove_input_rule(self, protocol, port):
        return "iptables -D INPUT -p " + protocol + " --dport " + port + " -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"

    def build_remove_output_rule(self, protocol, port):
        return "iptables -D OUTPUT -p " + protocol + " --sport " + port + " -m conntrack --ctstate ESTABLISHED -j ACCEPT"
