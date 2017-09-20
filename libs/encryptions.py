import base64


## encrypt: function to base64 encode and encrypt user, command and message
def encrypt(user, command, message):
    from configuration import cipher, maxpayload

    # Cipher and encode user
    padd = len(user) % 16
    if padd > 0: user = user + (' ' * (16 - padd))
    encoded_user = base64.b64encode(cipher.encrypt(user))

    # Cipher and encode command
    padd = len(command) % 16
    if padd > 0: command = command + (' ' * (16 - padd))
    encoded_command = base64.b64encode(cipher.encrypt(command))

    # Cipher and encode message
    padd = len(message) % 16
    if padd > 0: message = message + (' ' * (16 - padd))
    encoded_message = base64.b64encode(cipher.encrypt(message))

    # Calculate total packet length
    cipheredsize = len(encoded_user)+len(encoded_command)+len(encoded_message)
    packetsize = 48
    chunksize = maxpayload - cipheredsize - packetsize

    return encoded_user,encoded_command,encoded_message,chunksize

## decrypt: function to decrypt received packet fields and return them as a list
def decrypt(user,command,message,payload):
    from configuration import cipher
    try:
        dec_user = cipher.decrypt(base64.b64decode(user)).strip()
        dec_command = cipher.decrypt(base64.b64decode(command)).strip()
        dec_message = cipher.decrypt(base64.b64decode(message)).strip()
        dec_payload = cipher.decrypt(base64.b64decode(payload)).strip()
        return dec_user,'',dec_command,dec_message,dec_payload,True
    except:
        return '','','','','',False
