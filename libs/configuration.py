# -*- coding: utf-8 -*-​
import argparse, time
import configparser
import logging
import log
from Crypto.Cipher import AES
from random import randint
from utils import nick_selection, channel_selection
logger = logging.getLogger(__name__)

global conf
global maxpayload
global sc
global lastpacketsc
global userlist
global bootime
global pktcount
global pktcounts
global pktcountw
global pktcountpb
global pktcountpbd
global pingcount
global pingsc
global broadcast
global username
global privateircname
global privateirc
global remote
global verbose
global channel
global repeater
global pcount
global cipher
global intfmon
global uuid
global raspberry

def init_variables():
    global maxpayload
    global sc
    global lastpacketsc
    global userlist
    global bootime
    global pktcount
    global pktcounts
    global pktcountw
    global pktcountpb
    global pktcountpbd
    global pingcount
    global pingsc
    global broadcast
    global username
    global privateircname
    global privateirc
    global remote
    global raspberry
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
    remote = []
    raspberry = "0"

def create_cipher():
    from utils import channel_password
    global cipher
    iv = b"1234567890123456"
    password = channel_password()
    cipher = AES.new(password, AES.MODE_OPENPGP, iv)
    cipher.encrypt(iv)

def argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Expecify a configuration file.", default="CCC.conf")
    args = parser.parse_args()
    return args


def configuration_parser(config_file):
    global username
    global privateircname
    global privateirc
    global channel
    global verbose
    global repeater
    global pcount
    global intfmon
    global uuid
    logger.info("Reading config file")
    config = configparser.ConfigParser()
    config.read(config_file)
    if len(config.read(config_file)) == 0:
        log.critical_errors("Couldn't open configuration file.")
    if not config.has_section("general"):
        log.critical_errors("No general section found in config file.")
    elif not config.has_option("general", "debug"):
        log.critical_errors("No debug level found in config file.")
    else:
        verbose = int(config["general"]["debug"])
    log.config_log(config)
    if config.has_option("general","interface"):
        if config["general"]["interface"][:4] == 'wlan' or config["general"]["interface"][:3] == 'mon' or config["general"]["interface"][:2] == 'wl':
            intfmon = str(config["general"]["interface"])
        else:
            print "Interface must be wlanx, monx or wlpx!"
            exit(-1)
    else:
        intfmon = str(raw_input("Enter your Wi-Fi interface: "))
    if intfmon == '': intfmon = str(config["general"]["interface"])
    if config.has_option("general","raspberry"):
        raspberry = config["general"]["raspberry"]
    from interface_actions import InitMon
    if not InitMon(intfmon): exit(-1)
    if not config.has_option("general", "username"):
        nick_selection()
    else:
        print "Using nickname: %s" % config["general"]["username"]
        username = str(config["general"]["username"])
    if not config.has_option("general", "channel"):
        privateirc, privateircname = channel_selection()
    else:
        print "Using chat room: %s" % config["general"]["channel"]
        privateircname = config["general"]["channel"]
        privateirc = (config["general"]["channel"] * ((16 / len(config["general"]["channel"])) + 1))[:16]
    from utils import calculate_channel, md5, getmac
    channel = calculate_channel()
    uuid = md5(getmac(intfmon))[7:14]
    repeater = int(config["general"]["repeater"])
    pcount = int(config["general"]["pcount"])
    return config


def init_config():
    global conf
    init_variables()
    conf = configuration_parser(argument_parser().config)
