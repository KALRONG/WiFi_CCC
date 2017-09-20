#!/usr/bin/python
# -*- coding: utf-8 -*-​
# to-do: send files (receive in sync order and with integrity)
import logging
from Crypto.Cipher import AES
from threading import Thread
from random import randint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 

# User defined variables
verbose=0  ## debug level (1-3)
pcount=6  ## number of packet 
repeater=0  ## act also as repeater of other nodes
history=1  ## remember commands
defaultinterface='wlan1'  

# System variables
maxpayload=258
sc=randint(1,1024)
lastpacketsc=[]
userlist={}
bootime=time.time()
pktcount=0
pktcounts=0
pktcountw=0
pktcountpb=0
pktcountpbd=0
pingcount=0
pingsc=[]
broadcast='ff:ff:ff:ff:ff:ff'

from libs.interface_actions import packetSniffer, PacketProcessSend, SetChannel
from libs.utils import banner, utilization, cleanexit, channel_password
from libs.configuration import init_config, username, privateircname, channel

def main():
    banner()
    init_config()
    if conf["general"]["history"]:
        try:
            import readline
            histfile = os.path.join(".chat_history")
            readline.read_history_file(histfile)
            readline.set_history_length(1000)
        except IOError:
            pass
    # Cipher suite: never use ECB in other place than a PoC
    cipher = AES.new(channel_password(), AES.MODE_ECB)
    SetChannel(channel)
    sniffer = Thread(target=packetSniffer)
    sniffer.daemon = True
    sniffer.start()
    utilization()
    try:
        PacketProcessSend("%s joined the chat room: %s" % (username, privateircname))  ## User entering group
        while 1:
            chat = raw_input()
            if chat != ":exit:":
                sys.stdout.write("\033[F")  # Cursor up one line
                if chat != '':
                    PacketProcessSend(chat)
            else:
                cleanexit()
    except KeyboardInterrupt:
        cleanexit(histfile)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cleanexit(history)


