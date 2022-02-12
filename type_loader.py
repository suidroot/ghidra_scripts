# C type data into Data Types
# @author @suidroot
# @category suidroot
# @keybinding 
# @menupath 
# @toolbar 


from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.app.util.cparser.C import CParser


filename = askFile("Typedef Txt file", "Open")
typedef_txt = open(filename.toString(), 'r').read()

print (typedef_txt)

# Get Data Type Manager
data_type_manager = currentProgram.getDataTypeManager()

# Create CParser
parser = CParser(data_type_manager)

# Parse structure
parsed_datatype = parser.parse(typedef_txt)

# Add parsed type to data type manager
datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
