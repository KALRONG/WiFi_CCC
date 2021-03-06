#!/usr/bin/python
# -*- coding: utf-8 -*-​
# to-do: send files (receive in sync order and with integrity)
import logging, os, sys
from threading import Thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def main():
    from libs.utils import banner, utilization, cleanexit, join_channel
    from libs.configuration import conf, create_cipher
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
    create_cipher()
    from libs.interface_actions import packetSniffer, PacketProcessSend, SetChannel
    SetChannel()
    sniffer = Thread(target=packetSniffer)
    sniffer.daemon = True
    sniffer.start()
    utilization()
    join_channel()
    try:
        #PacketProcessSend(":chat:%s joined the chat room: %s" % (username, privateircname))  ## User entering group
        #PacketProcessSend(":chat: %s left the chat room: %s!" % (str(username), str(privateircname)))  ## User lefts group
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
    import libs.log as log
    import libs.configuration as config

    log.init_logging()
    config.init_config()
    main()



