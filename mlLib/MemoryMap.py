# Initializes project memory map
# @category MagicLantern

from mlLib.toolbox import *
from mlLib.MemTable import *


def createMemoryMap(device, fw):
    
    # First, init "target" memTable with general memory regions and RAM config
    memTable = MemTable()
    for region in device.cpu.regions:
        memTable.addRegion(region)
    memTable.createRAMEntries(device.memSize)

    print("Device")
    print(memTable)

    # Create another memory table, with camera specific regions
    fwTable = MemTable()
    for region in fw.roms:
        fwTable.addRegion(region)
    print("ROM files")
    print(fwTable)

    for e in fw.romcpy:
        fwTable.addRomcpyRegion(e)
        fwTable.clearRegion(e, "ROMCPY")
    print("ROMCPY added")
    print(fwTable)

    # remove firmware blobs
    for name, regions in fw.blobs.items():
        for region in regions:
            fwTable.clearRegion(region, name)
    print("Blobls removed")
    print(fwTable)

    # Inject camera specific entries on top of a target memory table
    memTable.merge(fwTable)
    print("Merged")
    print(memTable)

    # split subregions - after merge, as those may set own ACLs.
    for e in fw.subregions:
        memTable.splitSubregion(e)
    print("Subregions")
    print(memTable)

    memTable.removeDummyRegions()
    print("Cleanup")
    print(memTable)

    # add overlay regions
    # last step as those are independent of main address space
    for name, regions in fw.overlays.items():
        for region in regions:
            memTable.addRomcpyRegion(region)
            memTable.clearRegion(region, name)

    print("Memory map with overlays")
    print(memTable)
    return memTable

def applyMemoryMap(memTable, program = None):
    if not isinstance(memTable, MemTable):
        print("memTable is not MemTable object!")
        
    if program is None:
        from __main__ import currentProgram
        program = currentProgram
       
    def setAttrs(mb, attr):
        if len(attr) < 4:
            attr.ljust(4)
        mb.setRead(True if attr[0] == "r" else False)
        mb.setWrite(True if attr[1] == "w" else False)
        mb.setExecute(True if attr[2] == "x" else False)
        mb.setVolatile(True if attr[3] == "v" else False)
        mb.setSourceName('AutoLoader')

    mem = program.getMemory()

    for r in memTable:
        rStart = stringToAddress(r.dst, program = program)
        print("Create region: 0x{:08x} {}".format(r.dst, r.name))
        region = None
        #if isinstance(r, ByteMappedRegion):
        #    region = mem.createByteMappedBlock(r.name, rStart, stringToAddress(r.src, program=program), r.getSize(), r.overlay)
        if isinstance(r, RomRegion):
            fileBytes = getFileBytes(r.file, program=program)

            region = mem.createInitializedBlock(r.name, rStart, fileBytes, r.offset, r.getSize(), r.overlay)
        elif isinstance(r, UninitializedRegion):
            region = mem.createUninitializedBlock(r.name, rStart, r.getSize(), r.overlay)

        region.setComment(r.comment)
        setAttrs(region, r.acl)