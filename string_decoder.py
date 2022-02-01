# Malware XOR String decoder
# @author: suidroot
# @category: suidroot

from string import printable

def bnot(val):
    return ~val & 255

def multi_selection_decode(key):
   
    start = currentSelection.getMinAddress()
    end = currentSelection.getMaxAddress()

    current_address = start

    while True:

        dec_string = decoder(current_address, key)
        actions(current_address, dec_string)
        current_address = getInstructionAfter(current_address).getAddress()

        if current_address >= end:
            break

def decoder(location, key):
    hex_str = currentProgram.getListing().getInstructionAt(location).getOpObjects(1)[0].toString()[2:]
    dec_string = xor_convert_string(hex_str, key)
    # clean unprintable chars (casues decompile to fail)
    return filter(lambda x: x in printable, dec_string)

def actions(current_address, dec_string):
    print("Address: %s - String:  %s" % (current_address, dec_string))
    setEOLComment(current_address, dec_string)

def current_line_decode(key):
    dec_string = decoder(currentAddress, key)
    actions(currentAddress, dec_string)

    return dec_string

def xor_convert_string(hex_str, key):
    dec_string = ''
    for i in range(0, len(hex_str), 2):
        dec_string += chr(int(hex_str[i:i+2], 16) ^ key)
    dec_string = dec_string[::-1]

    return dec_string
    
key = askString("Key", "Key")

if '~' in key:
    key = bnot(int(key[1:], 16))
else:
    key = int(key, 16)


if currentSelection is None:
    current_line_decode(key)
else:
    multi_selection_decode(key)