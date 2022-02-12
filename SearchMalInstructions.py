# Search for suspect instructions
#@author suidroot
#@category suidroot
#@keybinding 
#@menupath Tools.Search for suspect instructions
#@toolbar 


from binascii import hexlify

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
# import time
from java.awt import Color

highlight_color = Color.RED
vmevasion_neumonics = [ "SIDT", "SGDT", "SLDT", "SMSW", "STR", "IN", "CPUID"] 
xor_ignore = [ "RSP", "RBP", "EBP", "RSP", "ESP" ]  # registers to ignore in 2nd operand of XOR


service = state.getTool().getService(ColorizingService)
if service is None:
    print ("Can't find ColorizingService service")

listing = currentProgram.getListing()
func = getFirstFunction()
entryPoint = func.getEntryPoint()
instructions = listing.getInstructions(entryPoint, True)

# monitor.initialize(len(instructions))

for instruction in instructions:
    addr = instruction.getAddress()
    oper = instruction.getMnemonicString()

    # look for some VM evasion techniques
    if oper in vmevasion_neumonics:
        createBookmark(addr,"Note","Potential VM Evasion")
        service.setBackgroundColor(addr, addr, highlight_color)
        print("Potential VM Evasion: 0x{} : {}".format(addr, instruction))

    # Look for possible XOR encryption operations
    elif oper == "XOR":
        if instruction.getOpObjects(0)[0] != instruction.getOpObjects(1)[0]:
            if str(instruction.getOpObjects(1)[0]) not in xor_ignore:
                createBookmark(addr,"Note","Potential XOR Encryption")
                service.setBackgroundColor(addr, addr, highlight_color)
                print("Potential XOR Encryption: 0x{} : {}".format(addr, instruction))

    # monitor.checkCanceled() # check to see if the user clicked cancel
    # time.sleep(1) # pause a bit so we can see progress
    # monitor.incrementProgress(1) # update the progress
    # monitor.setMessage("Working on " + str(i)) # update the status message

# func = getFirstFunction()
# while func is not None:
#     if func.getName() in 
#     print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
#     func = getFunctionAfter(func)

