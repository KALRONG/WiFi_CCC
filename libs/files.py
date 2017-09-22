# -*- coding: utf-8 -*-​
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
        num_parts = len(textwrap.wrap(fileContent, chunksize, break_on_hyphens=False))
        parts = textwrap.wrap(fileContent, chunksize-len(str(num_parts)), break_on_hyphens=False)
        encoded_parts=set()
        count = 0
        encoded_parts.add(base64.b64encode(cipher.encrypt("%s:%s" % (filename, num_parts))))
        for part in parts:
            part = "%s:%s" % (count, part)
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
