from mlLib.toolbox import *
from pprint import pprint
from copy import copy
 
class MemTable(object):
    """
    Representation of memory table
    """
    
    CHECK_FINE = -1
    CHECK_FAIL = -2
    
    def __init__(self):
        """
        Constructs MemTable object
        """
        self._table =  []
        
    def __iter__(self):
        """
        Make object iterable from a contained list
        """
        return iter(self._table)
        
    def __str__(self):
        """
        Implements string conversion. Renders ascii table representation of
        object content.
        """
        buf = ""

        if len(self._table) == 0:
            return "Table is empty\n"

        for e in self._table:
            rType = type(e).__name__
            desc = ""
            acl = e.acl if e.acl else "????"
            if isinstance(e, ByteMappedRegion):
                rType += " 0x{:08x}".format(e.src)
            if isinstance(e, RomRegion):
                desc += " <- {}".format(e.file)
                desc += " +0x{:08x}".format(e.offset)
            isOverlay = "o" if e.overlay else " "
            buf += "0x{:08x} - 0x{:08x} : {} : {} : {} : {} : {} : {}\n".format(
                        e.dst, e.end, acl, isOverlay, rType.ljust(28),
                        desc.ljust(28), e.name.ljust(30), e.comment)
        buf += "Total items: {}".format(len(self._table))
        buf += "\n"
        
        return buf

    def _sort(self):
        """
        Sorts internal table by region address, puts overlays at the end.
        """
        self._table.sort(key=lambda d: (d.overlay, d.dst))

    def _checkRegionFit(self, target):
        """
        Check if region fits into any existing region
        
        :param target: Region class object to search
        :return:       ID if region fits another region
        :return:       MemTable.CHECK_FINE if region has no conflicts
        :return:       MemTable.CHECK_FAIL if region conflicts other boundaries
        """
        for i in range(0, len(self._table)):
            # dismiss overlays
            if self._table[i].overlay:
                continue
            
            rDst = self._table[i].dst
            rEnd = self._table[i].end
            
            if target.dst >= rDst and target.dst <= rEnd:
                # target starts in this region
                if target.end <= rEnd:
                    # target fits into this region (FIT)
                    return i
                else:
                    # target conflicts region from above (OVERFLOW)
                    return MemTable.CHECK_FAIL
            elif target.dst < rDst:
                # target starts below this region
                if target.end <= rDst:
                    # target ends below this region (skip)
                    continue
                else:
                    # target conflicts region from below (OVERFLOW)
                    return MemTable.CHECK_FAIL
            else:
                # target starts above this region (skip)
                continue
        
        return MemTable.CHECK_FINE

    def addRegion(self, region):
        """
        Add a new memory region. Check for possible conflicts.

        :param region: Region object to add
        """
        if not region.overlay:
            result = self._checkRegionFit(region)
            if result != MemTable.CHECK_FINE:
                print("addRegion: Region conflict: {}".format(region.name))
                exit(1)
        self._table.append(region)
        self._sort()

    def _makeSubregion(self, sourceId, region):
        """
        Inject region / split region into another region.
        Region to be injected must fit into a destination region.
        
        :param region:   Region class object to inject
        :param sourceId: ID of destination region
        """
        oldEntry = self._table.pop(sourceId)
        rStart = region.dst
        rEnd = region.end
        if rEnd != oldEntry.end:
            # injected region is not at the end
            # create "upper region"
            e = copy(oldEntry)
            # adjust start pointer
            e.dst = region.end + 1
            if isinstance(oldEntry, RomRegion):
                # adjust file offset
                e.offset = region.end - oldEntry.dst + oldEntry.offset + 1
            self.addRegion(e)
        
        if rStart != oldEntry.dst:    
            # injected region is not at start
            # create "lower region"
            e = copy(oldEntry)
            # adjust end pointer
            e.end = rStart - 1;
            self.addRegion(e)
        
        newRegion = None
        if isinstance(region, SubRegion):
            # request to create a subregion from existing region
            
            # Keep all data from the original region, except those defined in SubRegion object
            newRegion = copy(oldEntry)
            newRegion.dst = region.dst
            newRegion.end = region.end
            if region.name: 
                newRegion.name = region.name
            if region.comment:
                newRegion.comment = region.comment
            
            # copy old ACL if not overwritten
            if region.acl:
                newRegion.acl = region.acl

            # fix fileOffset if needed
            if isinstance(oldEntry, RomRegion):
                newRegion.offset = region.dst - oldEntry.dst + oldEntry.offset

        else:
            # inject new region
            newRegion = copy(region)   
        
        #copy ACL
        if not newRegion.acl:
            newRegion.acl = oldEntry.acl

        self.addRegion(newRegion)
       
    def merge(self, src):
        """
        Mege entries from src table into current object.
        Inject regions that overlap, add regions that have no counter-part.
        
        
        :param src: Table to fetch entries from.
        """
        for region in src:
            if region.overlay:
                # overlays don't conflict with regular address space
                self.addRegion(region)
                continue
                
            result = self._checkRegionFit(region)
            if result == MemTable.CHECK_FAIL:
                print("merge: Region conflicts: {}".format(region.name))
                exit(1)
            elif result == MemTable.CHECK_FINE:
                self.addRegion(region)
            else:
                self._makeSubregion(result, region)

    def addRomcpyRegion(self, region):
        """
        Add a new Romcopy region

        :param region: RomRegion object to add
        """
        result = self._checkRegionFit(DummyRegion(dst = region.src, size=region.getSize()))
        if result < 0:
            print("addRomcpyRegion: Source region not found: {}".format(region.name))
            exit(1)
        if not isinstance(self._table[result], RomRegion):
            print("addRomcpyRegion: Source region is not a file!")
            exit(1)
        src = self._table[result]

        rSrcOff  = region.src - src.dst + src.offset
        
        region = copy(region)
        region.file = src.file
        region.offset = region.src - src.dst + src.offset
        region.comment = "ROMCPY_{}_0x{:08x}".format(region.name,region.src)
        if region.overlay and not region.acl:
            # if no ACL was set, default to source region ACL.
            region.acl = src.acl
            
        self.addRegion(region)
       
    def clearRegion(self, region, name=""):
        """
        Replace region with uninitialized bytes
        
        :param region: RomRegion object to add
        :param name:   New region name to append in comment.
        """
        if region.clear == False:
            return
            
        result = self._checkRegionFit(DummyRegion(dst = region.src, size=region.getSize()))
        if result < 0:
            print("Source region not found: {} {}".format(name, region.name))
            exit(1)

        comment = "removed blob 0x{:08x}: {} {}".format(region.dst, name, region.name)
        name = "{}_blob".format(self._table[result].name)
        self._makeSubregion(result, UninitializedRegion(
            name = name, acl="----", comment = comment, dst = region.src, size=region.getSize())
            )

    def splitSubregion(self, region):
        """
        Split region out of a bigger region
        
        :param region: Region object to split out.
        """
        result = self._checkRegionFit(region)
        if result < 0:
            print("Split: source region not found for {}".format(region.name))
            exit(1)
        pprint(result)
        print(region.name)
        self._makeSubregion(result, region)
        
    def removeDummyRegions(self):
        """
        Remove all placeholder regions (DummyRegion objects)
        """
        for e in self._table[:]: # iterate over a copy
            if isinstance(e, DummyRegion):
                self._table.remove(e)

    def createRAMEntries(self, ramSize):
        """
        Create memory regions for RAM entries.

        It requires CPU DummyRegion RAM entries to exist before execution.


        TODO: This is a hack.
              Should this be moved out ouf this class?
              Should those be just defined as two regions in camera definition?

        :param ramSize: size of RAM to generate
        """

        # Cacheable RAM. Always ends below 0x40000000
        end = (ramSize if ramSize <= 0x40000000 else 0x40000000) - 1
        srcRegion = self._checkRegionFit(DummyRegion(dst=end, size=0))
        if srcRegion < 0:
            print("addRomcpyRegion: Source region not found: {}".format(region.name))
            exit(1)

        dst = self._table[srcRegion].dst
        size = end - dst + 1
        rCached = UninitializedRegion(name="RAM CACHED", dst = dst, size = size)
        self._makeSubregion(srcRegion, rCached)

        # Uncacheable RAM. Always starts at 0x40000000
        rUncached = UninitializedRegion(name="RAM UNCACHED", dst = 0x40000000, size = ramSize)
        srcRegion = self._checkRegionFit(rUncached)
        if srcRegion < 0:
            print("Unable to fit uncacheable RAM into existing address space, aborting!")
            exit(1)
        self._makeSubregion(srcRegion, rUncached)


class Region(object):
    """
    Abstract memory region
    """
    def __init__(self, dst, size, name = "", comment = "", acl = None, overlay=False):
        self.name = name
        self.dst = dst
        self.acl = acl
        self.comment = comment
        self.overlay = overlay
        self.setSize(size)

    def setSize(self, size):
        #self.size = size
        self.end = self.dst + size - 1
        
    def getSize(self):
        return self.end - self.dst + 1
    
class RomRegion(Region):
    """
    Memory region loaded from a ROM file.
    """
    def __init__(self, file, offset=0, **kwargs):
        self.file = file
        self.offset = offset
        super(RomRegion, self).__init__(**kwargs)

class UninitializedRegion(Region):
    """
    Memory region with uninitialized data
    """
    def __init__(self, **kwargs):
        super(UninitializedRegion, self).__init__(**kwargs)
        
class ByteMappedRegion(RomRegion):
    """
    Memory region byte mapped from another region
    """
    def __init__(self, src, clear = True, **kwargs):
        self.src = src
        self.offset = None
        self.clear = clear
        super(ByteMappedRegion, self).__init__(file = "", **kwargs)

class DummyRegion(Region):
    """
    Memory region used as a default settings provider for other regions.
    Removed from a final memory map.
    """
    def __init__(self, **kwargs):
        super(DummyRegion, self).__init__(**kwargs)
        
class SubRegion(Region):
    """
    Memory region that describes a sub region of existing Region
    """
    def __init__(self, **kwargs):
        super(SubRegion, self).__init__(**kwargs)
        




class RegionList(object):
    """
    Describes a list of Region objects
    """
    def __init__(self, *regions):
        self._list = []

        for region in regions:
            self._list.append(region)
        
    def __iter__(self):
        """
        Make object iterable from a contained list
        """
        return iter(self._list)
    
    @staticmethod
    def validateDict(obj, name):
        if not isinstance(obj, dict):
            print("{} is not RegionList, aborting!").format(name)
            pprint(obj)
            exit(1)
        for name, region in obj.items():
            RegionList.validate(region, name)
    
    @staticmethod
    def validate(obj, name):
        if not isinstance(obj, RegionList):
            print("{} is not RegionList, aborting!").format(name)
            pprint(obj)
            exit(1)


class CPU(object):
    """
    Describes a single CPU variant
    """
    def __init__(self, arch, lang, compiler, regions):
        RegionList.validate(regions, "regions")
        
        self.arch = arch
        self.lang = lang
        self.compiler = compiler
        self.regions = regions
        
    @staticmethod
    def validate(obj, name):
        if not isinstance(obj, CPU):
            print("{} is not CPU, aborting!").format(name)
            pprint(obj)
            exit(1)
            
class Device(object):
    """
    Describes a single device
    """
    def __init__(self, cpu, memSize, firmwares = {}):
        # validate types
        Firmware.validateDict(firmwares, "firmware")
        CPU.validate(cpu, "cpu")

        self.cpu = cpu
        self.memSize = memSize
        self.firmwares = firmwares
        
class Firmware(object):
    """
    Description of a single firmware version
    """
    def __init__(self, roms, romcpy = RegionList(), subregions = RegionList(), blobs = {}, overlays = {} ):
        # validate types
        RegionList.validate(roms, "roms")
        RegionList.validate(romcpy, "romcpy")
        RegionList.validate(subregions, "subregions")
        RegionList.validateDict(blobs, "blobs")
        RegionList.validateDict(overlays, "overlays")
        
        self.roms = roms
        self.blobs = blobs
        self.romcpy = romcpy
        self.overlays = overlays
        self.subregions = subregions
    
    @staticmethod
    def validateDict(obj, name):
        if not isinstance(obj, dict):
            print("{} is not Firmware, aborting!").format(name)
            pprint(obj)
            exit(1)
        for name, firmware in obj.items():
            Firmware.validate(firmware, name)
    
    @staticmethod
    def validate(obj, name):
        if not isinstance(obj, Firmware):
            print("{} is not Firmware, aborting!").format(name)
            pprint(obj)
            exit(1)
