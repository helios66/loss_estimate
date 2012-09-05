
def hex2bytes(hex, columns=16):
	result = ""
	for line in hex.split("\n"):
		prefix = line[:3*columns]
		for character in prefix.split():
			result = result + chr(eval("0x" + character))
	return result

def has_ascii_nul(s):
	return s.find("\x00") != -1
