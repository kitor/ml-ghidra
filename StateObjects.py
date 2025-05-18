# Populates StateObject state change functions and details
# @category MagicLantern

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.NamespaceUtils import getNamespacesByName
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import ParameterDefinitionImpl


from mlLib.toolbox import *
from mlLib.decompiler import *


def getStateChangeFunctions(addr, inputs, states):
    """
    Return list of unique functions addressess in StateObject definition

    :param addr:   Address of the structure (CreateStateObject arg3)
    :param inputs: Number of inputs (CreateStateObject arg4)
    :param states: Number of states (CreateStateObject arg5)
    :return: List of Ghidra address objects.
    """
    results = []
    # This is a list of structs with 2 members, we need 2nd member.
    # It is just more convinient to go back 4 bytes and then iterate +8
    addr = addr.subtract(4)
    for i in range(0, inputs * states):
       addr = addr.add(8)
       #print(curAddr)
       fn = getPointerAddr(addr)
       #print(fn)
       # Save only valid and unique addresses. 0 is considered invalid.
       if (fn.getOffset() > 0) and not fn in results:
           results.append(fn)

    return results

def prepareStateChangeFnSignature(fn):
    """
    Prepare function signature for processing.

    Verifies if function has defined any arguments.
    If missing, tries first to recover them from Decompiler, and if all fails
    adds arbitrary arg1.

    :param fn:  Ghidra Function object
    "return::   FunctionSignature object
    """
    sig = fn.getSignature()
    if (len(sig.getArguments()) == 0) or \
            fn.getSignatureSource() == SourceType.DEFAULT:
        # Function either had no args set, or autonalaysis
        # was not confident about decomiler-discovered args.
        # State change functions WILL have at least one arg,
        # thus force args from decompilation as they are better
        # than nothing.
        sig = getFnSignatureFromDecomp(fn)
        if (len(sig.getArguments()) == 0):
            # We somehow still have no args. Create arbitrary arg1
            # just so we can progress
            args = [
                ParameterDefinitionImpl("arg1", getDataTypes("int")[0], None) ]
            sig.setArguments(args)
            print(fn.getName() + ": added arbitrary arg1")
        else:
            print(fn.getName() + ": commited args from decomp")

    return sig

def setStateChangeFnSignatures(pointers, prefix = None, oldPrefix = None,
            namespace = None, datatype = None, argName = None):
    """
    Sets signatures of state change functions.

    Depending on arguments set it can set function name prefix, namespace
    and apply name / datatype to 1st function argument (usually class)

    For namespace and datatype options they must exist before function is used.

    :param pointers:  List of Ghidra Address objects to functions
    :param prefix:    String with prefix to prepend function names with (opt.)
    :param oldPrefix: String with prefix to cut from function name (opt.)
    :param namespace: Parent namespace to assign to function (opt.)
    :param datatype:  Data type to assign to a function (opt.)
    :param argName:   Name to update arg1 name with (opt., only if datatype set)
    """

    for addr in pointers:
        # Get rid of thumb bit if set
        if addr.getOffset() & 0x1:
            addr = addr.subtract(1)

        # Get function. Create if it was missing.
        fn = getFunctionAt(addr)
        if not fn:
            fn = createFunction(addr, None)
            print(newName + ": Created missing function")

        # Set function name prefix
        oldName = fn.getName()
        if prefix and not oldName.startswith(prefix):
            if oldName.startswith("FUN_"):
                oldName = oldName[4:]
            elif oldPrefix and oldName.startswith(oldPrefix):
                oldName = oldName[len(oldPrefix):]

            newName = prefix + "_" + oldName
            print(newName + ": Renamed from " + fn.getName())
            fn.setName(newName, SourceType.USER_DEFINED)

        # Set namespace
        if namespace:
            print(fn.getName() + ": namespace set to " + namespace.getName())
            fn.setParentNamespace(namespace)

        # Set arg1 datatype and (optional) name
        if datatype:
            sig = prepareStateChangeFnSignature(fn)

            sig.getArguments()[0].setDataType(datatype)
            if argName:
                sig.getArguments()[0].setName(argName)

            # Commit signature back
            cmd = ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED)
            cmd.applyTo(currentProgram, monitor)


pointers = getStateChangeFunctions(
        addr = toAddr(0xe0a89d3c),
        inputs = 0x1b,
        states = 1 )

setStateChangeFnSignatures(
        pointers = pointers,
        prefix = "PS",
        namespace = getNamespacesByName(currentProgram, None, "PropState")[0],
        datatype = getDataTypes("PropMgr_class *")[0],
        argName = "pObj" )
