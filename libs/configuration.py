import argparse, time
import configparser
import logging
import log
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
global remote
global verbose
global channel
global repeater
global pcount

maxpayload=258
sc=randint(1,1024)
lastpacketsc=[]
#userlist={}
bootime=time.time()
pktcount=0
pktcounts=0
pktcountw=0
pktcountpb=0
pktcountpbd=0
pingcount=0
pingsc=[]
broadcast='ff:ff:ff:ff:ff:ff'


def argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Expecify a configuration file.", default="CCC.conf")
    args = parser.parse_args()
    return args


def configuration_parser(config_file):
    from interface_actions import InitMon
    global verbose
    global repeater
    global pcount
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
        verbose = config["general"]["debug"]
    if not config.has_option("general","interface"):
        if config["general"]["interface"][:4] == 'wlan' or config["general"]["interface"][:3] == 'mon':
            interface = config["general"]["interface"]
        else:
            print "First argument must be wlanx or monx!"
            exit(-1)
    else:
        interface = raw_input("Enter your Wi-Fi interface: ")
    if interface == '': interface = config["general"]["interface"]
    if not InitMon(interface): exit(-1)
    if not config.has_option("general", "username"):
        nick_selection()
    else:
        print "Using nickname: %s" % config["general"]["username"]
    if not config.has_option("general", "channel"):
        channel_selection()
    else:
        print "Using chat room: %s" % config["general"]["channel"]
    repeater = config["general"]["repeater"]
    pcount = config["general"]["pcount"]
    return config


def init_config():
    global conf
    log.init_logging()
    conf = configuration_parser(argument_parser().config)