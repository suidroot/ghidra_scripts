# Malware XOR String decoder
# @author: suidroot
# @category: suidroot

from string import printable

def bnot(val):
    ''' Run Binary NOT on byte value '''
    return ~val & 255

def current_line_decode(key):
    ''' Run decoder on currently selected line '''
    dec_string = decoder(currentAddress, key)
    print("Address: %s - String:  %s" % (currentAddress, dec_string))

    actions(currentAddress, dec_string)

    return dec_string

def multi_selection_decode(key):
    ''' Run decodder when mulitple lines are selected '''
    start = currentSelection.getMinAddress()
    end = currentSelection.getMaxAddress()
    current_address = start
    action_string = ''

    while True:
        dec_string = decoder(current_address, key)
        
        if dec_string != "":
            action_string += dec_string
        print("Address: %s - String:  %s" % (current_address, dec_string))

        current_address = getInstructionAfter(current_address).getAddress()

        if current_address >= end:
            actions(end, action_string)

            break

def decoder(location, key):
    ''' Load, decode, and decrypt strings '''

    # Load current line Mnemonic for the current line
    mnemonic = currentProgram.getListing().getInstructionAt(location).getMnemonicString()

    # Determine if direct load or using MMX to load from data section
    if mnemonic == 'MOV':
        hex_list = load_single_line(location)
    elif mnemonic == 'MOVUPS':
        hex_list = find_and_load_data(location)
    else:
        hex_list = None 

    if hex_list != None:
        dec_string = list_xor_convert_string(hex_list, key)
        # clean unprintable chars (casues decompile to fail)
        return_val = filter(lambda x: x in printable, dec_string)
    else:
        return_val = ""
    
    return return_val

def actions(current_address, dec_string):
    setEOLComment(current_address, dec_string)


def list_xor_convert_string(hex_list, key):
    ''' Decrypt from list of bytes to string '''

    dec_string = ''
    for i in hex_list:
        dec_string += chr(i ^ key)

    return dec_string

def find_and_load_data(start_address, data_len=16, mnemonic='MOVAPS'):
    ''' Search backward for specific instrcution and load data from .data section. Return list for bytes '''
    loop_counter = 0
    current_address = start_address
    while True:
        # break if if search more then 10 instructions back
        if loop_counter > 10:
            print('too many loops')
            data_list = []
            break

        current_instruction = getInstructionBefore(current_address)
        if current_instruction.getMnemonicString() == mnemonic:
            data_address = currentProgram.getListing().getInstructionAt(current_instruction.getAddress()).getOpObjects(1)[0].toString()[2:]
            data_list = getBytes(parseAddress(data_address), data_len).tolist()
            break

        current_address = current_instruction
        loop_counter += 1
    # swap 2s compliment
    data_list = [ i & 255 for i in data_list]
    return data_list

def load_single_line(location, operand=1):
    ''' Load bytes from specificied operand, return list of bytes '''

    operand = currentProgram.getListing().getInstructionAt(location).getOpObjects(operand)[0].toString()

    if '0x' in operand:
        hex_str = operand[2:]
        if (len(hex_str) % 2) != 0:
            hex_str = '0' + hex_str
        hex_list = []
        for i in range(0, len(hex_str), 2):
            hex_list.append(int(hex_str[i:i+2], 16))
        
        return_val = hex_list[::-1]
    else:
        return_val = None

    return return_val

def main():
    key = askString("Key", "Key")

    if '~' in key:
        key = bnot(int(key[1:], 16))
    else:
        key = int(key, 16)

    if currentSelection is None:
        current_line_decode(key)
    else:
        multi_selection_decode(key)

if __name__ == "__main__":
    main()