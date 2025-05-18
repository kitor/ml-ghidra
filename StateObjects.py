# Populates all StateObject state change functions and details
# @category MagicLantern

from mlLib.stateObjects import *

CreateStateObjectAddress = toAddr(0x0003d970)

StateObjectEntryType = CreateStateObjectEntryDataType()
results = getStateObjects(CreateStateObjectAddress)

for entry in results:
    name, struct, inputs, states = entry
    print("processing " + name)
    setStateObjectConfigDataType(StateObjectEntryType, struct, inputs, states)

    pointers = getStateChangeFunctions(
            addr = struct,
            inputs = inputs,
            states = states )

    setStateChangeFnSignatures(
            pointers = pointers,
            prefix = name)