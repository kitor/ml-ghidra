from ghidra.util.task import ConsoleTaskMonitor

from ghidra.app.decompiler import DecompileOptions, DecompInterface

from ghidra.program.model.listing import FunctionSignature
from ghidra.program.model.pcode import FunctionPrototype
from ghidra.program.model.data import ParameterDefinitionImpl
from ghidra.program.model.data import FunctionDefinitionDataType

def getFnSignatureFromDecomp(fn, program=None):
    """
    Get function signature from decomp

    In some cases (where fn args were not commited yet, and autoanalysis
    had low confidence on function signature), code returns function signature
    without params / return type set. This may not be the result you want.

    This function attempts to recive signature from decompiler so it can be
    applied to affected function.

    TODO: Check if return type is kept.

    :param func: Ghidra Function object
    """
    
    if program is None:
        from __main__ import currentProgram
        program = currentProgram
        
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    res = ifc.decompileFunction(fn, 60, monitor)
    hfp = res.getHighFunction().getFunctionPrototype()
    args = []
    for i in range(hfp.getNumParams()):
        p = hfp.getParam(i)
        args.append(ParameterDefinitionImpl(p.getName(), p.getDataType(), None))

    fdt = FunctionDefinitionDataType(fn.getSignature())
    fdt.setArguments(args)
    return fdt