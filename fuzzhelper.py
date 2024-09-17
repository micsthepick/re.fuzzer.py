def cleanstring(string):
    return ''.join(c for c in string if (ord(c) < 0xd800 or ord(c) >= 0xe000) and (ord(c) < 0x7f or ord(c) > 0x9f) and ord(c) >= 0x20)
