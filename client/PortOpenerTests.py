from RuleManager import RuleManager
import time

"""
    Testing that the port is opening / closing the IPTABLES rules as expected
"""
if __name__ == '__main__':
    pOpener = RuleManager()

    pOpener.manage_port_rules("TCP", "192.168.0.18", "8505", 5, True)
    print("Expect instant print of this because new thread starts in manage_port_rules")

    # wait for thread to finish doing work (in normal cases this would not be needed)
    time.sleep(10)