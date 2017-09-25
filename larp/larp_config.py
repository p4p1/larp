import os
from time import gmtime, strftime
from termcolor import colored

class configure():
    """ class to configure larp """
    def __init__(self, verbose, cfg_path=None):
        self.v = verbose
        if cfg_path == None:
            self.cfg_path = os.environ['HOME']+"/.config/larp/config"
        else:
            self.cfg_path = cfg_path
        self.cfg = dict()
        if not os.path.exists(self.cfg_path):
            self.error("configuration, does not exists")

    def error(self, msg="", level=0):
        print colored("[!!] "+msg, "red")

    def data_isok(self):
        try:
            if self.cfg['GATEWAY'] and self.cfg['INTERFACE'] and\
                    self.cfg['IP_PATH']:
                        return True
        except:
            self.error("No configuration present in file", 1)


    def configure(self):
        if not os.path.exists(self.cfg_path):
            return None
        with open(self.cfg_path, "r") as fp:
            for line in fp:
                if "#" in line:
                    continue
                elif "GATEWAY" in line:
                    self.cfg['GATEWAY'] = line.split('=')[1].strip()
                elif "INTERFACE" in line:
                    self.cfg['INTERFACE'] = line.split('=')[1].strip()
                elif "IP_PATH" in line:
                    self.cfg['IP_PATH'] = line.split('=')[1].strip()
                elif "RATE" in line:
                    self.cfg['RATE'] = line.split('=')[1].strip()
            self.data_isok()
            fp.close()
        return self.cfg

    def gen_config_wiz(self):
        print colored("[*] Enter the gateway of the network:", "blue")
        gateway = raw_input(">>")
        print colored("[*] Enter the interface you wish to use:", "blue")
        interface = raw_input(">>")
        print colored("[*] Enter the path of the list of ip's:", "blue")
        ip_path = raw_input(">>")
        print colored("[*] Enter the rate per second of arp packets:", "blue")
        rate = raw_input(">>")
        print colored("[*] Thank you for using gen_config_wizard!", "green")
        self.gen_config(gateway, interface, ip_path, rate)

    def gen_config(self, gateway, interface, ip_path, rate):
        if not os.path.exists(os.environ['HOME']+"/.config/larp"):
            os.makedirs(os.environ['HOME']+"/.config/larp")
        with open(os.environ['HOME']+"/.config/larp/config", "w") as fp:
            cfg_str = "# config file for larp,\n# <3\n\nGATEWAY=%s\nINTERFACE=%s\nIP_PATH=%s\nRATE=%s\n" % (gateway, interface, ip_path, rate)
            fp.write(cfg_str)
            fp.close()


if __name__ == "__main__":
    print configure().configure()
