# Populates StateObject state change functions and details
# @category MagicLantern

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.NamespaceUtils import getNamespacesByName
from ghidra.program.model.symbol import SourceType

from mlLib.toolbox import *
from mlLib.decompiler import *


def getStateChangeFunctions(ptr, inputs, states):
    """
    Return list of unique functions addressess in StateObject definition

    :param ptr:    Address of the structure (CreateStateObject arg3)
    :param inputs: Number of inputs (CreateStateObject arg4)
    :param states: Number of states (CreateStateObject arg5)
    :return: List of Ghidra address objects.
    """
    results = []
    curAddr = ptr.subtract(4) # just more convinient
    for i in range(0, inputs*states):
       curAddr = curAddr.add(8)
       fn = stringToAddress(getPtrFromMemory(curAddr))
       # Save only unique, valid addresses. 0 is considered invalid.
       if (fn.getOffset() > 0) and not fn in results:
           results.append(fn)

    return results


def setStateChangeFnSignatures(inputs, prefix = None, namespace = None,
            datatype = None, argName = None):
    """
    Sets signatures of state change functions.

    Depending on arguments set it can set function name prefix, namespace
    and apply name / datatype to 1st function argument (usually class)

    For namespace and datatype options they must exist before function is used.

    :param inputs:    List of Ghidra Address objects to functions
    :param prefix:    String with prefix to prepend function names with (opt.)
    :param namespace: Parent namespace name to assign to function (opt.)
    :param datatype:  Name of data type to assign to a function (opt.)
    :param argName:   Name to update arg1 name with (opt., only if datatype set)
    """
    dt = None
    if datatype:
        dt = getDataTypeByName(datatype)

    for p in inputs:
        if p.getOffset() & 0x1:
            # get rid of thumb bit
            p = p.subtract(1)

        print(p)
        fn = getFunctionContaining(p)
        if not fn:
            # Probably function was not created, try to do it now
            createFunction(p, "FUN_" + str(p))
            fn = getFunctionContaining(p)

        oldName = fn.getName()

        if prefix and not oldName.startswith(prefix):
            if oldName.startswith("FUN_"):
                oldName = oldName[4:]
            print(prefix + "_" + oldName)
            fn.setName(prefix + "_" + oldName, SourceType.USER_DEFINED)

        if namespace:
            oldNs = fn.getParentNamespace()
            if oldNs and oldNs.getName() != namespace:
                newNs = getNamespacesByName(currentProgram, None, namespace)
                print(type(newNs))
                fn.setParentNamespace(newNs[0])

        if datatype:
            sig = fn.getSignature()
            if (len(sig.getArguments()) == 0) and \
                    fn.getSignatureSource() == SourceType.DEFAULT:
                # function had no args set, get them from decompiler
                sig = getFnSignatureFromDecomp(fn)

            # Update 1st arg
            sig.getArguments()[0].setDataType(dt)
            if argName:
                sig.getArguments()[0].setName(argName)

            # Commit signature back
            cmd = ApplyFunctionSignatureCmd(p, sig, SourceType.USER_DEFINED)
            cmd.applyTo(currentProgram, monitor)


fns = getStateChangeFunctions(stringToAddress("0xe0a7e6c4"), 21, 10)
setStateChangeFnSignatures(fns, "EVF", "EvfState", "EvfClass *", "pObj")
