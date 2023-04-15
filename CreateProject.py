# Creates a project for EOS ROM analysis
# @category MagicLantern

from mlLib.toolbox import createNewProgram, createFileBytes
from mlLib.MemoryMap import *
from cfg.memory import devices

# TODO: GUI
model = "77D"
ver   = "1.1.0"

device = devices[model]
fw = device.firmwares[ver]

from mlLib.gui.FilesLoader import loadFiles, loadFilesError
files = loadFiles(fw.roms)
if not files or len(files) < len(fw.roms):
    # not all files loaded successfully, abort
    loadFilesError()
    exit(1)
      
memoryMap = createMemoryMap(device, ver)

newProgram = createNewProgram("{}_{}".format(model, ver), device.cpu.arch, device.cpu.lang, device.cpu.compiler)

# create file bytes in program
for name, provider in files.items():
    createFileBytes(name, provider, program=newProgram)
    
# we need to explicitly pass new program downsteram as scripts are confused
applyMemoryMap(memoryMap, program=newProgram)
