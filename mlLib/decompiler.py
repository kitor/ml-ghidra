from __main__ import *

from ghidra.util.task import ConsoleTaskMonitor

from ghidra.app.decompiler import DecompileOptions, DecompInterface

from ghidra.program.model.listing import FunctionSignature
from ghidra.program.model.pcode import FunctionPrototype
from ghidra.program.model.data import ParameterDefinitionImpl
from ghidra.program.model.data import FunctionDefinitionDataType

from mlLib.toolbox import *

def getFnSignatureFromDecomp(fn):
    """
    Get function signature from decomp

    In some cases (where fn args were not commited yet, and autoanalysis
    had low confidence on function signature), code returns function signature
    without params / return type set. This may not be the result you want.

    This function attempts to recive signature from decompiler so it can be
    applied to affected function.

    :param func: Ghidra Function object
    """
    # TODO: Check if return type is kept.

    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(fn, 60, monitor)
    hfp = res.getHighFunction().getFunctionPrototype()
    args = []
    for i in range(hfp.getNumParams()):
        p = hfp.getParam(i)
        args.append(ParameterDefinitionImpl(p.getName(), p.getDataType(), None))

    fdt = FunctionDefinitionDataType(fn.getSignature())
    fdt.setArguments(args)
    return fdt


def getCallOps(addr):
    """
    Get operands of a function call

    Based on https://github.com/HackOvert/GhidraSnippets

    :param addr: Valid adress object with function call
    :return:     Inputs of operand at :address:
    """
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    func = getFunctionContaining(addr)
    res = ifc.decompileFunction(func, 60, monitor)
    high_func = res.getHighFunction()
    pcodeops = high_func.getPcodeOps(addr)
    op = pcodeops.next()
    return op.getInputs()

def uniqueToString(op):
    """
    Decode OperandInput from getUniqueValue into a string

    :param op: Operand to decode value from
    :return:   String with decoded value
    """
    return hex(op.getOffset()).rstrip("L")

def nodeToUint(node):
    return node.getHigh().getScalar().getValue() & 0xFFFFFFFF

def getUniqueValue(node):
    """
    Attempt to decode a value from PcodeOps

    For constant values returns a value.
    For unique values attempts to follow the chain.

    see https://github.com/NationalSecurityAgency/ghidra/discussions/3711

    TODO: Return computed value instead of operand input objects.
          This will become handy when properly working with PTRSUB and others.

    :param node: Single PcodeOps node to decode:
    :return:     Operand input
    """
    if node.isUnique():
        tmp = node.getDef()
        inp = tmp.getInputs()
        if len(inp) == 1:
            if tmp.getMnemonic() == "CAST":
                return getUniqueValue(inp[0])
            else:
                return nodeToUint(inp[0])
        elif len(inp) == 2 and tmp.getMnemonic() == "PTRSUB":
            if inp[0].isConstant():
                if inp[1].isConstant():
                    return nodeToUint(inp[1])
                else:
                    print("getUniqueValue rr")
            else:
                return getUniqueValue(inp[0])

    elif node.isConstant():
        return nodeToUint(node)
    elif node.isAddress():
        # double pointer? pcode.HighGlobal
        return getPointerAddr(node.getAddress()).getOffset()
    else:
        # We can do nothing for HighParam (comes from call args)
        # and for HighOther (undefined data, or data structure)
        return None


def decodeCallArgs(addr):
    """
    Decodes arguments of CreateStateObject function call

    TODO: Return arguments instead of printing them

    :param addr: Valid adress object with function call
    """
    data = []
    try:
        ops = getCallOps(addr)
        for arg in ops[1:]:
           data.append(getUniqueValue(arg))
    except Exception as e:
        print("Exception: {}".format(e))

    return data