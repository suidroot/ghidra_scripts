# ARM Bit Unmapper
# @author: @suidroot
# @category: suidroot
# @toolbar: 
# @menupath suidroot


def binary(num, length=32):
    return format(num, '#0{}b'.format(length + 2))

def find_base_addr(bitmapped):
    if (0x22000000 < bitmapped and bitmapped < 0x23FFFFFF):
        bit_band_base = 0x22000000
        base_address = 0x20000000
    elif (0x42000000 < bitmapped and bitmapped < 0x43FFFFFF):
        bit_band_base = 0x42000000
        base_address = 0x40000000
    else:
        bit_band_base = 0
        base_address = 0
    return bit_band_base, base_address

def bitunmapper(bitmapped):
    bit_band_base, base_address = find_base_addr(bitmapped)
    unmap_port = int(((bitmapped - bit_band_base) & 0xfffff00) / 32)
    unmap_bits = int((bitmapped & 0x000000FF) / 4)
    if unmap_bits > 32:
        unmap_port += 0x4
        unmap_bits %= 32
    baseaddress = base_address + int(unmap_port)

    # TODO: Get Label info for the unmapped Addresses
    # data_info = currentProgram.getListing().getDataAt(parseAddress(str(hex(baseaddress & 0xFFFFFF00))[:-1])).toString()
    # register_info = currentProgram.getListing().getDataAt(parseAddress(str(hex(baseaddress)))).toString()

    print("Full Register Address: " + hex(baseaddress))
    print("Base Port: " + hex(baseaddress & 0xFFFFFF00)[:-1])
    print("Register Offset: " + hex(baseaddress & 0x000000FF))
    print("Bit Map: " + binary(unmap_bits))
    # print("Port Data Location Info: " + data_info)
    # print("Register Data Location Info: " + register_info)


bit_address = askString("Address to Decode", "Address")

if '0x' not in bit_address:
    bit_address = '0x' + bit_address

bitunmapper(int(bit_address,16))