import textwrap, base64


## filecrypt: function to split files in small parts and encrypt them
def filecrypt(filename, chunksize):
    from configuration import cipher
	try:
		with open(filename, mode='rb') as payload:
			fileContent = payload.read()
	except:
		fileContent=''
		print ":chat: cannot open requested file: %s" %filename
		return ''
	try:
		parts = textwrap.wrap(fileContent, chunksize)
		encoded_parts=set()
		for part in parts:
			lastpadd = len(part) % 16
			if lastpadd > 0:
				part = part + ("~" * (16 - lastpadd))
			encoded_part = base64.b64encode(cipher.encrypt(part))
			encoded_parts.add(encoded_part)
		return encoded_parts
	except Exception as e:
		print ":chat: error disecting file: %s. %s" %(filename, e.message)
		return ''