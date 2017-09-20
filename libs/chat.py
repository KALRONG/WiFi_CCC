import textwrap, base64, subprocess
from scapy.all import *
from encryptions import decrypt
from configuration import remote, userlist


## chatcrypt: function to cut payload in max size parts, cipher and encode each part
def chatcrypt(payload, chunksize):
    from configuration import cipher
    parts=set()
    if len(payload) > chunksize:
        parts = textwrap.wrap(payload, chunksize)
    else:
        parts.add(payload)

    encoded_parts=set()
    for part in parts:
        lastpadd = len(part) % 16
        if lastpadd > 0: part = part + (' ' * (16 - lastpadd))
        encoded_part = base64.b64encode(cipher.encrypt(part))
        encoded_parts.add(encoded_part)
    return encoded_parts


## cmdcrypt: function to execute shell command, split output in parts and encrypt them
def cmdcrypt(execute,chunksize):
    from configuration import cipher
    try:
        execsplit = execute.split(" ")
        p = subprocess.Popen(execsplit, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        parts = out.rstrip("\n")
        parts = parts.splitlines()
        encoded_parts=set()
        for part in parts:
            print ":chat: executed [%s] -> %s" %(execute, part)
            lastpadd = len(part) % 16
            if lastpadd > 0: part = part + (' ' * (16 - lastpadd))
            encoded_part = base64.b64encode(cipher.encrypt(part))
            encoded_parts.add(encoded_part)
        return encoded_parts
    except:
        return ''


def PacketHandler(pkt):
    from configuration import verbose, repeater, pcount
    global lastpacketsc, pktcount, pktcountpb, pktcountpbd, pktcountw, pingcount, pingsc
    pktcount += 1

    if pkt.addr3.upper() == ':'.join(remote).upper():
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
