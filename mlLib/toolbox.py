


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
