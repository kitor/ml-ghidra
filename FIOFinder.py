from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol.SourceType import *


def stringToAddress(addr):
    """
    Create Ghidra address object from string containing address
    
    :param addr: String with address representation
    :return:     Ghidra address object
    """
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr)


def convToBytes(addr, len=4):
    """
    Ghidra getBytes, but returns actual unsigned bytes instead of signed representations
    
    :param addr: Valid adress object of in-memory string
    :param len:  Buffer len to read.
    :return:     Map with read bytes
    """
    return map(lambda b: b & 0xff, getBytes(addr,len))


def getPtrFromMemory(addr):
    """
    Decode 32 bit LE value from a memory space into a string representation

    TODO: Shall this be left as a string? Makes it easy to use stringToAddress
          for decoding pointers, and avoiding nonsense with lack of unsinged 
          values in Python
    
    :param addr: Valid adress object of in-memory string
    :return:     String representation of a value, encoded as base 16
    """
    data = convToBytes(addr,4)
    val = data[0] + (data[1] << 8) + (data[2] << 16) + (data[3] << 24)
    return hex(val).rstrip("L")


def getStringFromMemory(addr, len=0x64):
    """
    Naive cstring string decoder
    
    :param addr: Valid adress object of in-memory string
    :param len:  Maximum buffer len to decode.
    :return:     Decoded string
    """
    msg = bytearray(convToBytes(addr, len))
    result = ""
    try:
        return msg.decode().split('\x00')[0]
    except UnicodeDecodeError as e:
        return msg.decode(errors="ignore").split('\x00')[0]


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
                return inp[0]
        elif len(inp) == 2 and tmp.getMnemonic() == "PTRSUB":
            if inp[0].isConstant() and inp[1].isConstant():
                return inp[1]
    elif node.isConstant:
        return node.getHigh().getScalar()
    else:
        return None


def decodeCallArgs(addr, argNo):
    """
    Decodes arguments of CreateStateObject function call
     
    TODO: Return arguments instead of printing them

    :param addr: Valid adress object with function call 
    """
    name = "N/A"
    
    try:
        ops = getCallOps(addr)
        data = getUniqueValue(ops[argNo])
        print("Data: {}".format(data))
    except Exception as e:
        print("Exception: {}".format(e))
    
    return data


def runFinder(refs, mnemonic, argNo):
    results = {}
    for ref in refs:
        addr = ref.getFromAddress()
        ins = getInstructionAt(addr)
        # TODO: This is a very naive method, using disassembler to get "CALL" shall be better
        # TODO: Attempt to find thunks, and process them too?
        if ins.getMnemonicString().startswith(mnemonic):
            print ("branch at {}, {}".format(addr.toString(), ins.toString()))
            name = decodeCallArgs(addr, argNo)
            if not name in results.keys():
               results[name] = []
            
            results[name].append(addr)
        else:
            print ("not a branch at {}, {}".format(addr.toString(), ins.toString()))
            
    return results


def nameFunctions(calls, prefix = "", stub_names = None):
    stubs = {}
    for name, ptrs in calls.items():
        sources = []
        for p in ptrs:
            fn = getFunctionContaining(p)
            sources.append(fn)
            
        sources = list(set(sources)) #keep unique values
        if len(sources) > 1:
            print("{}: Multiple functions found, skipping! {}".format(name, sources))
        else:
            if not prefix or name.startswith(prefix):
                newName = name
            else:
                newName = "{]{}".format(prefix, name)
            func = sources[0]
            pFunc = sources[0].getEntryPoint()
            print("Rename {} as {}".format(sources[0], newName))
            func.setName(newName, USER_DEFINED)
            if stub_names and name in stub_names:
                ml_name = stub_names[name]
                print(" + Create a label with ML name {}".format(ml_name))
                createLabel(pFunc, ml_name, False)
                stubs[stub_names[name]] = (pFunc, name)
                
    return stubs


def printStubs(stubs):
    print("Insert into stubs.S: ")
    for name, data in stubs.items():
        if name[0] != "_":
           name = " " + name
        addr = data[0]
        comment = data[1]
        tmp = "THUMB_FN(0x{}, {})".format(addr, name).ljust(50)
        print("{}// {}".format(tmp, comment))


FIO_ML1 = {
    "Open"      : "_FIO_OpenFile",
    "Create"    : "_FIO_CreateFile",
    "Remove"    : "_FIO_RemoveFile",
    "Read"      : "_FIO_ReadFile",
    "Search"    :  "FIO_SeekSkipFile",
    "Write"     : "_FIO_WriteFile",
    "Close"     :  "FIO_CloseFile",
    "AcqSize"   : "_FIO_GetFileSize64",
    "Rename"    : "_FIO_RenameFile",
    "CreateDir" : "_FIO_CreateDirectory",
    "Flush"     :  "FIO_Flush",
    "FirstEnt"  : "_FIO_FindFirstEx",
    "NextEnt"   :  "FIO_FindNextEx",
    "CloseEnt"  :  "FIO_FindClose"
    }

FIO_ML2 = {
    "FIO_OpenFile"        : "_FIO_OpenFile",
    "FIO_CreateFile"      : "_FIO_CreateFile",
    "FIO_RemoveFile"      : "_FIO_RemoveFile",
    "FIO_ReadFile"        : "_FIO_ReadFile",
    "FIO_SeekSkipFile"    :  "FIO_SeekSkipFile",
    "FIO_WriteFile"       : "_FIO_WriteFile",
    "FIO_CloseFile"       :  "FIO_CloseFile",
    "FIO_GetFileSize64"   : "_FIO_GetFileSize64",
    "FIO_RenameFile"      : "_FIO_RenameFile",
    "FIO_CreateDirectory" : "_FIO_CreateDirectory",
    "FIO_Flush"           :  "FIO_Flush",
    "FIO_FindFirstEx"     : "_FIO_FindFirstEx",
    "FIO_FindNextEx"      :  "FIO_FindNextEx",
    "FIO_FindClose"       :  "FIO_FindClose"
    }
# Get all *known* xrefs to FIO_logger()
refs = getReferencesTo(toAddr("FIO_logger"))

# Note: This will fail if function is not yet defined
# On fail, just go to the address and create a missing function.
# Repeat until it won't fail.
calls = runFinder(refs, "bl", 1)
stubs = nameFunctions(calls, "FIO_", FIO_ML2)

#refs = getReferencesTo(toAddr("mzrm_functable_logger"))
#calls = runFinder(refs, "callx8", 3)
#stubs = nameFunctions(calls)
#printStubs(stubs)
