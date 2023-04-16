# Test memory map generation, without applying or creating a new program
# @category MagicLantern

from mlLib.MemoryMap import *
from mlLib.gui.FirmwareSelector import selectFirmware

from cfg.memory import devices

device, fw = selectFirmware(devices)

createMemoryMap(device, fw)
