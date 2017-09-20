import logging
logger = logging.getLogger(__name__)
from scapy.all import *
from encryptions import decrypt, encrypt
from files import filecrypt
from utils import next_sc
from chat import chatcrypt, cmdcrypt
from configuration import remote, userlist


## InitMon: function to initialize monitor mode vif
def InitMon(interface):
    from configuration import verbose, intfmon
    if not os.path.isdir("/sys/class/net/" + interface):
        logging.error("WiFi parent interface %s does not exist! Cannot continue!" %interface)
        return False
    else:
        intfmon = 'mon' + interface[-1]
        if os.path.isdir("/sys/class/net/" + intfmon):
            if verbose > 1: logging.debug('DEBUG', 33, "WiFi interface %s exists! Deleting it!" % (intfmon))
            try:
                os.system("iw dev %s del" % intfmon)
                time.sleep(0.3)
            except OSError as e:
                logging.error("Could not delete monitor interface %s" % intfmon)
                os.kill(os.getpid(), SIGINT)
                return False
        try:
            # create monitor interface using iw
            os.system("iw dev %s interface add %s type monitor" % (interface, intfmon))
            time.sleep(0.2)
            os.system("rfkill block %s" %interface[-1])
            time.sleep(0.2)
            os.system("ifconfig %s down" %interface)
            time.sleep(0.2)
            os.system("iwconfig %s mode monitor" %interface)
            time.sleep(0.2)
            os.system("rfkill unblock %s" %interface[-1])
            time.sleep(0.2)
            os.system("ifconfig %s up" %interface)
            if verbose > 1: logging.debug("Creating monitor VAP %s for parent %s..." %(intfmon, interface))
        except OsError as e:
            logging.error("Could not create monitor %s" % intfmon)
            os.kill(os.getpid(), SIGINT)
            return False
        return True


def packetSniffer():
    from configuration import intfmon
    try:
        sniff(iface=intfmon, prn=PacketHandler, store=False, lfilter=lambda pkt: (Dot11ProbeReq in pkt))
    except Exception as e:
        logger.error("Error starting sniffer!")
        print "Error starting sniffer! %s" % e.message
        print "algo %s" % intfmon
        exit()


## PacketHandler: function to proccess received packets if related to chat
def PacketHandler(pkt):
    from configuration import verbose, repeater, pcount, lastpacketsc, pktcount, pktcountpb, pktcountpbd, pktcountw, pingcount, pingsc, intfmon
    pktcount += 1

    if pkt.addr3.upper() == remote:
        try:
            elt = pkt[Dot11Elt]
            usr = command = message = payload = ''
            psc = str(pkt.SC)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 51:  ## AP Channel report
                    uuid = elt.info
                elif elt.ID == 7:  ## 7 country
                    ciphereduser = elt.info  ## ciphered user
                    if (ciphereduser + psc) in lastpacketsc:
                        pktcountpbd += 1
                        if verbose > 1: print "Packet discarded: %s" % (ciphereduser)
                        return  ## silently discard packet, processed before
                elif elt.ID == 16:  ## meassurement transmission
                    cipheredcommand = elt.info
                elif elt.ID == 221:  ## vendor/WPS
                    cipheredpayload = elt.info
                elif elt.ID == 66:  ## extended rates
                    cipheredmessage = elt.info
                elt = elt.payload

            if verbose > 1: print "Received (encrypted): %s,%s,%s,%s" % (
                ciphereduser, cipheredcommand, cipheredmessage, cipheredpayload)

            pktcountpb += 1
            decrypted = decrypt(ciphereduser, cipheredcommand, cipheredmessage, cipheredpayload)
            decrypteduser = decrypted[0]
            decryptedcommand = decrypted[2]
            decryptedmessage = decrypted[3]
            decryptedpayload = decrypted[4]
            decryptedok = decrypted[5]  ## last field is checksum
            if verbose > 1: print decrypted
            if verbose > 1: print "Received (decrypted): %s,%s,%s,%s" % (
                decrypteduser, decryptedcommand, decryptedmessage, decryptedpayload)

            if not decryptedok:
                if verbose: print "Malformed packet received!"
                return

            # Add user, if new, to the discovered users dictionary
            if not userlist.has_key(uuid): userlist[uuid] = decrypteduser

            # Show results of received packet
            pktcountw = + 1
            if decryptedcommand[:6] == ':msgs:':
                print "%s: %s" % (decrypteduser, decryptedpayload)
            elif decryptedcommand[:6] == ':ping:':
                if not psc + decrypteduser in pingsc:
                    pingsc.append(psc + decrypteduser)
                    pingcount = 0
                    print ""
                pingcount += 1
                sys.stdout.write("\033[F")  # Cursor up one line
                print "chat: %d/%s ping packets received from %s!" % (pingcount, decryptedmessage, decrypteduser)
            elif decryptedcommand[:6] == ':cmmd:':
                print "%s: executed [%s] -> %s" % (decrypteduser, decryptedmessage, decryptedpayload)
            elif decryptedcommand[:6] == ':chat:':
                print "chat: %s" % decryptedpayload
            elif decryptedcommand[:6] == ':file:':
                print "chat: file received [%s] -> %s" % (decryptedmessage, decryptedpayload[:8])
            else:
                print "(%s) %s[%s]: (%s) %s" % (
                    psc, decrypteduser, decryptedcommand, decryptedmessage, decryptedpayload)

            if not decryptedcommand[:6] == ':ping:':
                lastpacketsc.append(ciphereduser + psc)
            else:
                return

        except Exception as e:
            print e.message

        try:
            # Resend packet for the first time as a repeater if packet is not ours
            if repeater:
                if verbose: print "Repeating packet %s of user %s to the air" % (psc, decrypteduser)
                sendp(pkt, iface=intfmon, verbose=0, count=pcount)
        except:
            pass
        return


# PacketProcessSend: function to process user commands
def PacketProcessSend(chat):
    from configuration import verbose, pcount, username
    global sc,histfile
    user=username.strip()
    command = chat[:6]
    message = chat[6:]

    if command == ':chat:':
        encrypted = encrypt(user,command,message)
        chunksize = encrypted[3]
        payload=chatcrypt(message,chunksize)
        if verbose > 1: print "chat: %s" %(chat[6:])
        if verbose > 2: print encrypted
        PacketSend(encrypted,payload)
    elif command == ':file:':
        encrypted = encrypt(user,command,message)
        chunksize = encrypted[3]
        payload=filecrypt(message,chunksize)
        if verbose > 1: print encrypted
        print "chat: sending file %s" %message
        PacketSend(encrypted,payload)
    elif command == ':cmmd:':
        encrypted = encrypt(user,command,message)
        chunksize = encrypted[3]
        print "chat: executing command %s" %message
        if verbose > 2: print encrypted
        payload=cmdcrypt(message,chunksize)
        PacketSend(encrypted,payload)
    elif command == ':usrs:':
        print "chat: detected users: ",
        for useruuid,usr in userlist.items():
            print "%s(%s)" %(usr,useruuid),
        print ""
    elif command == ':ping:':
        message = str(pcount)
        encrypted = encrypt(user,command,message)
        chunksize = encrypted[3]
        payload = chatcrypt(chat,chunksize)
        if verbose > 2: print encrypted
        print "chat: sending %d ping packets..." %(pcount)  ## investigate why *5
        PacketSend(encrypted,payload)
    else:
        command = ':msgs:'
        encrypted = encrypt(user,command,message)
        chunksize = encrypted[3]
        payload = chatcrypt(chat,chunksize)
        if verbose > 2: print encrypted
        print "me: %s" %(chat)
        PacketSend(encrypted,payload)

## PacketSend: function to construct the packet to be sent
def PacketSend(encrypted,payload):
    from configuration import channel, verbose, broadcast, lastpacketsc, pktcounts, uuid, intfmon, pcount
    global uuid
    for part in payload: # ojo - revisar
        sc = next_sc()     ## Update sequence number
        if verbose > 1: print "\nsc:%s" %sc
        user=encrypted[0]
        command=encrypted[1]
        message=encrypted[2]
        payload=part
        ds="\x01"
        rates="x98\x24\xb0\x48\x60\x6c"

        # Forge Dot11packet
        dot11 = Dot11(type=0,subtype=4,addr1=broadcast, addr2=RandMAC(),addr3=remote)
        eltessid = Dot11Elt(ID=0,len=0,info='')
        eltrates = Dot11Elt(ID=1,len=len(rates),info=rates)
        eltchannel = Dot11Elt(ID=3,len=1,info=chr(channel))
        eltuser = Dot11Elt(ID=7,len=len(user),info=user) ## country
        eltuuid = Dot11Elt(ID=51,len=len(uuid),info=uuid) ## ap channel report
        eltcommand = Dot11Elt(ID=16,len=len(command),info=command)  ## meassurement transmission
        eltmessage = Dot11Elt(ID=66,len=len(message),info=message) ## extended rates
        eltpayload = Dot11Elt(ID=221,len=len(payload),info=payload) ## vendor/WPS
        dsset = Dot11Elt(ID='DSset',len=len(ds),info=ds)
        pkt = RadioTap()/dot11/Dot11ProbeReq()/eltessid/eltrates/eltchannel/eltpayload/eltuuid/eltuser/eltcommand/eltmessage/dsset
        pkt.SC = sc    ## Update sequence number
        lastpacketsc.append(user+str(sc))   ## Save this packet to not repeat showing it
        pkt.show()
        if verbose > 1: print "Sent: %s,%s,%s,%s" %(user,command,message,payload)

        try:
            sendp(pkt, iface=intfmon, verbose=0, count=pcount)  ## Send packet several times
            if verbose: print "Packet sent: %s" %(user)
            pktcounts += 1
        except Exception as e:
            print "Cannot send packet! %s" %e.message


def SetChannel():
    from configuration import intfmon, channel
    cmd0 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
    cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
    try:
        os.system(cmd0)
        os.system(cmd1)
        print "Setting %s to channel: %s and MAC: %s" % (intfmon, channel, remote)
    except:
        print "Error setting channel for %s" % intfmon
