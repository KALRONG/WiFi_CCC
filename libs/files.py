# -*- coding: utf-8 -*-​
import logging
logger = logging.getLogger(__name__)
import textwrap, base64


## filecrypt: function to split files in small parts and encrypt them
def filecrypt(filename, chunksize):
    try:
        with open(filename, mode='rb') as payload:
            fileContent = base64.b64encode(payload.read())
    except:
        fileContent=''
        print ":chat: cannot open requested file: %s" %filename
        return ''
    try:
        from configuration import cipher
        num_parts = str(len(textwrap.wrap(fileContent, chunksize, break_on_hyphens=False)))
        logger.debug("Number of parts: %s" % num_parts)
        logger.debug("Chunksize: %s" % (chunksize - len(num_parts) - 1))
        parts = textwrap.wrap(fileContent, chunksize-len(num_parts) - 1, break_on_hyphens=False)
        print parts
        encoded_parts=set()
        count = 1
        if len(num_parts) % 16 > 0:
            num_parts = num_parts+ ("~" * (16 - (len(num_parts)%16)))
        encoded_parts.add(base64.b64encode(cipher.encrypt("Parts: %s" % num_parts)))
        for part in parts:
            logger.debug("Part %s(%s): %s" % (count,len(part), part))
            part = "%s:%s" % (count, part)
            logger.debug("Part %s(%s): %s" % (count,len(part), part))
            lastpadd = len(part) % 16
            if lastpadd > 0:
                part = part + ("~" * (16 - lastpadd))
                encoded_part = base64.b64encode(cipher.encrypt(part))
                encoded_parts.add(encoded_part)
            count += 1
        return encoded_parts
    except Exception as e:
        print ":chat: error disecting file: %s. %s" %(filename, e.message)
        return ''

def remove_padding(message):
    i=len(message)-1
    while i >= 0:
        if message[i] == "~":
            i -= 1
        else:
            break
    return message[:i+1]
