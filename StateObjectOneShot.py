# Populates StateObject, one shot variant
# @category MagicLantern

from mlLib.stateObjects import *

StateObjectEntryType = CreateStateObjectEntryDataType()

struct = toAddr(0xe0a89d3c)
inputs = 0x1b
states = 1

pointers = getStateChangeFunctions(
         addr = struct,
         inputs = inputs,
         states = states )

setStateObjectConfigDataType(StateObjectEntryType, struct, inputs, states)

setStateChangeFnSignatures(
        pointers = pointers,
        prefix = "PS",
        oldPrefix = "PropState",
        namespace = getNamespacesByName(currentProgram, None, "PropState")[0],
        datatype = getDataTypes("PropMgr_class *")[0],
        argName = "pObj" )

