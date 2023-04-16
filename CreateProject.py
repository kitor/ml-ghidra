# Creates a project for EOS ROM analysis
# @category MagicLantern

from mlLib.MemoryMap import *
from mlLib.toolbox import createNewProgram, createFileBytes
from mlLib.gui.FilesLoader import loadFiles, loadFilesError
from mlLib.gui.FirmwareSelector import selectFirmware

from cfg.memory import devices

device, fw = selectFirmware(devices)

files = loadFiles(device, fw)
if not files or len(files) < len(fw.roms):
    # not all files loaded successfully, abort
    loadFilesError()
    exit(1)
      
memoryMap = createMemoryMap(device, fw)

newProgram = createNewProgram("{}_{}".format(device.model, fw.version),
        device.cpu.arch, device.cpu.lang, device.cpu.compiler)

# create file bytes in program
for name, provider in files.items():
    createFileBytes(name, provider, program=newProgram)
    
# we need to explicitly pass new program downsteram as scripts are confused
applyMemoryMap(memoryMap, program=newProgram)
