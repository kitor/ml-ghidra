# Creates a project for EOS ROM analysis
# @category MagicLantern

from time import sleep
from mlLib.toolbox import createNewProgram
from mlLib.MemoryMap import *
from cfg.memory import devices

model = "77D"
ver   = "1.1.0"
romDir = "D:/MagicLantern/ROMs/{}_{}".format(model, ver)
device = devices[model]
fw = device.firmwares[ver]

newProgram = createNewProgram("testProgram", device.cpu.arch, device.cpu.lang, device.cpu.compiler)

map = createMemoryMap(device, ver)

# we need to explicitly pass new program downsteram as scripts are confused
applyMemoryMap(map, romDir, program=newProgram)
