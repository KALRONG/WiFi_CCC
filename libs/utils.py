# -*- coding: utf-8 -*-​
import time, sys, readline
from Crypto.Hash import MD5


def current_timestamp():
    from configuration import bootime
    return (time.time() - bootime) * 1000000


def next_sc():
    from configuration import sc
    sc = (sc + 1) % 4096
    # return sc * 16  # Fragment number -> right 4 bits
    return sc


def md5(message):
    hash = MD5.new()
    hash.update(message)
    return hash.hexdigest()


def getmac(interface):
    try:
        mac = open('/sys/class/net/' + interface + '/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[0:17]

def cleanexit(histfile):
    from interface_actions import PacketProcessSend
    from configuration import username, pktcount, pktcountpb, pktcountw, pktcountpbd, pktcounts, privateircname
    try:
        PacketProcessSend(":chat:%s left the chat room: %s!" %(username, privateircname)) ## User lefts group
        readline.write_history_file(histfile)
        sys.stdout.write("\033[F") # Cursor up one line
        print "total packets:%s / processed:%s / written:%s / discarded:%s / sent: %s" %(pktcount,pktcountpb,pktcountw, pktcountpbd,pktcounts)
    except:
        print "bye!"
        pass
    exit()

def join_channel():
    from interface_actions import PacketProcessSend
    from configuration import username, privateircname
    try:
        PacketProcessSend(":chat:%s join the chat room: %s!" %(username, privateircname)) ## User joins group
    except:
        print "bye!"
        pass


def banner():
    print "======================================================="
    print "      ▌ ▌▗   ▛▀▘▗     ▞▀▖       ▞▀▖        ▞▀▖   "
    print "      ▌▖▌▄   ▙▄ ▄     ▌         ▌          ▌     "
    print "      ▙▚▌▐ ▄ ▌  ▐     ▌ ▖overt  ▌ ▖hannel  ▌ ▖hat"
    print "      ▘ ▘▀   ▘  ▀     ▝▀        ▝▀         ▝▀    "
    print "      SECRET & HIDDEN CHAT over WI-FI COVERT CHANNEL"
    print "======================================================="

def utilization():
    print "======================================================"
    print "Just write your message and press enter to send!"
    print "or you can use following commands:\n"
    print ":ping:         - ping all the other nodes (test)"
    print ":usrs:         - show all the detected users"
    print ":file:filename - send a file to all the users"
    print ":cmmd:command  - execute local command and send result"
    print ":exit:         - exit (press Ctrl+C if you are a pro!)"
    print "======================================================\n"

def nick_selection():
    from configuration import userlist, intfmon
    username = raw_input("Enter your User name or alias: ")
    if username == '': exit()
    if username[0] == ":": exit()
    uuid = md5(getmac(intfmon))[7:14]
    userlist[uuid] = username

def channel_selection():
    privateircname = raw_input("Define private IRC channel name: ")
    privateirc = (privateircname * ((16 / len(privateircname)) + 1))[:16]
    return privateirc, privateircname

def channel_password():
    privateirckey = raw_input("Define private IRC robust password: ")
    enckey = (privateirckey * ((16 / len(privateirckey)) + 1))[:16]
    return enckey


# Calculate channel to be used and mac address - TODO: mac derivation other way
def calculate_channel():
    from configuration import privateirc, remote
    global remote
    for i in range(0, 6):
        if i < 1:
            remote.append('61')
        else:
            letter = privateirc[i]
            remote.append(letter.encode("hex"))
        if i == 5: channel = max(min(11, ord(letter) / 10), 1)
        i += 1
    remote = ':'.join(remote).upper()
    return channel
