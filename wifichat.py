#!/usr/bin/python
# -*- coding: utf-8 -*-​
# to-do: send files (receive in sync order and with integrity)
import logging, os
from Crypto.Cipher import AES
from threading import Thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from libs.configuration import init_config

def main():
    init_config()
    from libs.interface_actions import packetSniffer, PacketProcessSend, SetChannel
    from libs.utils import banner, utilization, cleanexit, channel_password
    from libs.configuration import username, privateircname, channel, conf
    banner()
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
    main()



