# Test memory map generation, without applying or creating a new program
# @category MagicLantern

from mlLib.MemoryMap import *
from cfg.memory import devices

# TODO: GUI
model = "77D"
ver   = "1.1.0"
romDir = "D:/MagicLantern/ROMs/{}_{}".format(model, ver)
device = devices[model]
fw = device.firmwares[ver]

createMemoryMap(device, ver)
