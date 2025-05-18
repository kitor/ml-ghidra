from __main__ import *

def stringToAddress(addr, program = None):
    """
    Create Ghidra address object from string containing address

    :param addr: String with address representation
    :return:     Ghidra address object
    """
    if program is None:
        from __main__ import currentProgram
        program = currentProgram
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr)

def createNewProgram(name, arch, lang, compiler):
    from ghidra.program.util import DefaultLanguageService
    from ghidra.program.model.lang import Processor
    from __main__ import createProgram

    programName = name
    cpu = Processor.toProcessor(arch)
    langSvc = DefaultLanguageService.getLanguageService()
    langDescs = langSvc.getLanguageDescriptions(cpu)
    langDesc = next(x for x in langDescs if x.getLanguageID().toString() == lang)
    language = langSvc.getLanguage(langDesc.getLanguageID())

    compilerSpecDescs = langDesc.getCompatibleCompilerSpecDescriptions()
    compilerSpecDesc = next(x for x in compilerSpecDescs if x.getCompilerSpecName() == compiler)
    compilerSpec =  language.getCompilerSpecByID( compilerSpecDesc.getCompilerSpecID())

    return createProgram(programName, language, compilerSpec)

def getFileProvider(path, name):
    from __main__ import monitor
    from ghidra.formats.gfilesystem import FileSystemService
    from ghidra.formats.gfilesystem import FSRL

    path = "file://{}".format(path)

    # load new file from disk
    f = FSRL.fromString(path)
    fss = FileSystemService.getInstance()
    provider = fss.getByteProvider(f, False, monitor)
    return provider

def createFileBytes(name, provider, program=None):
    from __main__ import monitor

    if program is None:
        from __main__ import currentProgram
        program = currentProgram
    f = provider.getFile()
    bytes = program.getMemory().createFileBytes(name, 0, f.length(), provider.getInputStream(0), monitor)
    print("created new bytes {}".format(name))
    return bytes


def getFileBytes(name, program = None):
    from __main__ import monitor
    from ghidra.formats.gfilesystem import FileSystemService
    from ghidra.formats.gfilesystem import FSRL

    if program is None:
        from __main__ import currentProgram
        program = currentProgram

    # if file is already loaded, return it
    for e in program.getMemory().getAllFileBytes():
        if e.getFilename() == name:
            return e

    return False

def convToBytes(addr, len=4):
    """
    Ghidra getBytes, but returns actual unsigned bytes instead of signed representations

    :param addr: Valid adress object of in-memory string
    :param len:  Buffer len to read.
    :return:     Map with read bytes
    """
    from __main__ import getBytes
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

def getFirstDataType(name):
    dtm = getCurrentProgram().getDataTypeManager()
    r = []
    dtm.findDataTypes(name, r)
    if len(r) == 0:
        return None
    return r[0]

# Methods to get unsigned data variants borrowed from
# https://github.com/NationalSecurityAgency/ghidra/issues/1969#issuecomment-1221655969
def getUByte(addr):
    return getByte(addr) & 0xFF

def getUShort(addr):
    return getShort(addr) & 0xFFFF

def getUInt(addr):
    return getInt(addr) & 0xFFFFFFFF

def getULong(addr):
    return getLong(addr) & 0xFFFFFFFFFFFFFFFF

# Thanks @reyalp
def getPointerAddr(addr):
    return toAddr(getUInt(addr))