# Find and mark FIO stubs
# @category MagicLantern


from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol.SourceType import *

from mlLib.toolbox import *
from mlLib.decompiler import *

def runFinder(refs, mnemonic, argNo):
    results = {}
    for ref in refs:
        addr = ref.getFromAddress()
        ins = getInstructionAt(addr)
        # TODO: This is a very naive method, using disassembler to get "CALL" shall be better
        # TODO: Attempt to find thunks, and process them too?
        if ins.getMnemonicString().startswith(mnemonic):
            print ("branch at {}, {}".format(addr.toString(), ins.toString()))
            name = decodeCallArgs(addr)[argNo]
            if not name in results.keys():
               results[name] = []

            results[name].append(addr)
        else:
            print ("not a branch at {}, {}".format(addr.toString(), ins.toString()))

    return results


def nameFunctions(calls, prefix = "", stub_names = None):
    stubs = {}
    for name, ptrs in calls.items():
        print("namePtr: {} fns: {}".format(hex(name), ", ".join([ptr.toString() for ptr in ptrs])))
        name = getStringFromMemory(toAddr(name))
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
                newName = "{}{}".format(prefix, name)
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
# Get all *known* xrefs to DebugSTG_Printf
refs = getReferencesTo(toAddr("DebugSTG_Printf"))

# Note: This will fail if function is not yet defined
# On fail, just go to the address and create a missing function.
# Repeat until it won't fail.
calls = runFinder(refs, "bl", 0)
stubs = nameFunctions(calls, "FIO_", FIO_ML1)

#refs = getReferencesTo(toAddr("mzrm_functable_logger"))
#calls = runFinder(refs, "callx8", 3)
#stubs = nameFunctions(calls)
#printStubs(stubs)
