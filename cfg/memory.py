from mlLib.MemTable import *

cpus = {
    "DIGIC6": CPU(
        # https://magiclantern.fandom.com/wiki/Memory_map
        #
        # Digic 6 is a single core Cortex R4 CPU.
        # Memory map is based on MPU config.
        #
        # D6 has ROM1 at 0xFC000000 and a mirror at 0xFE000000.
        # Device starts from 0xFC000000 and quickly jumps to stage 1 bootloader at 0xFE...
        # Then stage 1 jumps to stage 2 ("firmware_entry") at 0xFC...
        # Both stage 1 and stage 2 appear to be position independent code (could run from both 0xFC... and 0xFE...)
        #
        # Stage 2 populates BTCM region and uses functions from there via thunks (like bzero32, create_init_task...)
        # init_task() is executed from 0xFE.., as well as everything else in DryOS.
        #
        # Some DryOS that work on ROM data areas (props, resources, etc) will reference 0xFC... range as data source.
        # But this is very rare.
        #
        # Please note that for better analysis purposes, we:
        # - populate only very early region of 0xFC... which jumps to stage 1 at 0xFE...
        # - keep all the other code (stage 2, DryOS ("program area") and everything else only in 0xFE... range.
        #
        # DIGIC6 have a secondary core called OMAR which is also ARM. This confuses autoanalysis a lot,
        # as they seem to live in a different memory space, using similar memory addresses.
        # There's also an Xtensa core called Zico (GPU core). Uses different architecture and shares ICU addres space.
        #
        # When preparing a device config, please add those (can be found via OmarLoader() and ZicoKick() functions)
        # into `blobs` section,
        arch = "ARM",
        lang = "ARM:LE:32:Cortex",
        compiler = "default",
        regions = RegionList (
            UninitializedRegion( dst=       0x0, size=    0x4000, acl="rwx-", name="ATCM" ),
                    DummyRegion( dst=    0x4000, size=0x3FFFC000, acl="rwx-", name="RAM CACHED"),
                    DummyRegion( dst=0x40000000, size=0x40000000, acl="rwx-", name="RAM UNCACHED"),
            UninitializedRegion( dst=0x80000000, size=   0x10000, acl="rwx-", name="BTCM" ),
            UninitializedRegion( dst=0xBFE00000, size=  0x200000, acl="rwx-", name="0xBFE..." ),
            UninitializedRegion( dst=0xC0000000, size=0x1FE00000, acl="rw-v", name="MMIO" ),
                    DummyRegion( dst=0xFC000000, size= 0x2000000, acl="r-x-", name="ROM1_MIRROR"),
                    DummyRegion( dst=0xFE000000, size= 0x2000000, acl="r-x-", name="ROM1")
        )
    ),
    "DIGIC7": CPU(
            # https://www.magiclantern.fm/forum/index.php?topic=19737.msg212603#msg212603
            #
            # D7 is a dual core Cortex A9 MP CPU.
            # Memory map is based on MMU config.
            #
            # Note: while MMU allows ROM1 execution, in all instances we know it is resources only ROM, thus it was set
            # as read only.
            #
            # D7 has two secondary Xtensa cores: Zico and Lime.
        arch = "ARM",
        lang = "ARM:LE:32:Cortex",
        compiler = "default",
        regions = RegionList (
            UninitializedRegion( dst=       0x0, size=    0x1000, acl="rwx-", name="CPU0 PRIV" ),
            UninitializedRegion( dst=    0x1000, size=    0x1000, acl="rwx-", name="CPU1 PRIV" ),
                    DummyRegion( dst=    0x2000, size=0x3FFFE000, acl="rwx-", name="RAM CACHED"),
                    DummyRegion( dst=0x40000000, size=0x80000000, acl="rwx-", name="RAM UNCACHED"),
            UninitializedRegion( dst=0xC0000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xC0000000" ),
            UninitializedRegion( dst=0xC4000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xC4000000" ),
            UninitializedRegion( dst=0xC8000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xC8000000" ),
            UninitializedRegion( dst=0xD0000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xD0000000" ),
            UninitializedRegion( dst=0xD2000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xD2000000" ),
            UninitializedRegion( dst=0xD4000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xD4000000" ),
            UninitializedRegion( dst=0xD8000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xD8000000" ),
            UninitializedRegion( dst=0xDE000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xDE000000" ),
            UninitializedRegion( dst=0xDF000000, size= 0x1000000, acl="rwx-", name="TCM" ),
                    DummyRegion( dst=0xE0000000, size= 0x8000000, acl="r-x-", name="ROM0"),
                    DummyRegion( dst=0xE8000000, size= 0x8000000, acl="r---", name="?" ),
                    DummyRegion( dst=0xF0000000, size= 0x8000000, acl="r---", name="ROM1"),
                    DummyRegion( dst=0xF8000000, size= 0x8000000, acl="r---", name="?" )
        )
    ),
    "DIGIC8": CPU(
            # https://www.magiclantern.fm/forum/index.php?topic=22770.msg212090#msg212090
            #
            # D8 is a dual core Cortex A9 MP CPU.
            # Memory map is based on MMU config. It is similar to DIGIC7, with changes in MMIO areas.
            #
            # Note: while MMU allows ROM1 execution, in all instances we know it is resources only ROM, thus it was set
            # as read only.
        arch = "ARM",
        lang = "ARM:LE:32:Cortex",
        compiler = "default",
        regions = RegionList (
            UninitializedRegion( dst=       0x0, size=    0x1000, acl="rwx-", name="CPU0 PRIV" ),
            UninitializedRegion( dst=    0x1000, size=    0x1000, acl="rwx-", name="CPU1 PRIV" ),
                    DummyRegion( dst=    0x2000, size=0x3FFFE000, acl="rwx-", name="RAM CACHED"),
                    DummyRegion( dst=0x40000000, size=0x80000000, acl="rwx-", name="RAM UNCACHED"),
            UninitializedRegion( dst=0xC0000000, size= 0x3000000, acl="rw-v", module="MMIO", name="MMIO 0xC0000000" ),
            UninitializedRegion( dst=0xC4000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xC4000000" ),
            UninitializedRegion( dst=0xC8000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xC8000000" ),
            UninitializedRegion( dst=0xCC000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xCC000000" ),
            UninitializedRegion( dst=0xD0000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xD0000000" ),
            UninitializedRegion( dst=0xD2000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xD2000000" ),
            UninitializedRegion( dst=0xD4000000, size= 0x2000000, acl="rw-v", module="MMIO", name="MMIO 0xD4000000" ),
            UninitializedRegion( dst=0xD7000000, size= 0x3000000, acl="rw-v", module="MMIO", name="MMIO 0xD7000000" ),
            UninitializedRegion( dst=0xDE000000, size= 0x1000000, acl="rw-v", module="MMIO", name="MMIO 0xDE000000" ),
            UninitializedRegion( dst=0xDF000000, size= 0x1000000, acl="rwx-", name="TCM" ),
                    DummyRegion( dst=0xE0000000, size= 0x8000000, acl="r-x-", name="ROM0"),
                    DummyRegion( dst=0xE8000000, size= 0x8000000, acl="r---", name="?" ),
                    DummyRegion( dst=0xF0000000, size= 0x8000000, acl="r---", name="ROM1"),
                    DummyRegion( dst=0xF8000000, size= 0x8000000, acl="r---", name="?" )
        )
    ),
    "DIGICX": CPU(
        # https://wiki.magiclantern.fm/cams:r6
        # https://www.magiclantern.fm/forum/index.php?topic=24827.msg230859#msg230859
        
        #00001000-00001FFF ? 00000000-00000FFF ( +0) O:NCACH I:WB,WA P:RW [ CPU0 only ]
        #00001000-00001FFF ? 00001000-00001FFF (-1000) O:NCACH I:WB,WA P:RW [ CPU1 only ]
        #00002000-3FFFFFFF ? 00001000-3FFFFFFF ( +0) O:NCACH I:WB,WA P:RW [ cacheable RAM - only the first GiB ]
        #40000000-BEFFFFFF ? 40000000-BEFFFFFF ( +0) O:NCACH I:NCACH P:RW [ uncacheable RAM - 2 GiB ]
        #BF000000-DEFFFFFF ? BF000000-DEFFFFFF ( +0) Device P:RW XN [ MMIO area ]
        #DF000000-DFFFFFFF ? DF000000-DFFFFFFF ( +0) O:NCACH I:WB,WA P:RW [ TCM? ]
        #E0000000-E7FFFFFF ? E0000000-E7FFFFFF ( +0) O:WB,WA I:WB,WA P:R [ main ROM ]
        #E8000000-EFFFFFFF ? E8000000-EFFFFFFF ( +0) Strongly-ordered P:RW XN [ ? ]
        #F0000000-F7FFFFFF ? F0000000-F7FFFFFF ( +0) O:WB,WA I:WB,WA P:R [ secondary ROM ]
        #F8000000-FFFFFFFF ? F8000000-FFFFFFFF ( +0) Strongly-ordered P:R XN [ ? ]
        
        arch = "ARM",
        lang = "ARM:LE:32:Cortex",
        compiler = "default",
        regions = RegionList (
            UninitializedRegion( dst=       0x0, size=    0x1000, acl="rwx-", name="CPU0 PRIV" ),
            UninitializedRegion( dst=    0x1000, size=    0x1000, acl="rwx-", name="CPU1 PRIV" ),
                    DummyRegion( dst=    0x2000, size=0x3FFFE000, acl="rwx-", name="RAM CACHED"),
                    DummyRegion( dst=0x40000000, size=0x7F000000, acl="rwx-", name="RAM UNCACHED"),
            UninitializedRegion( dst=0xBF000000, size=0x20000000, acl="rw-v", name="MMIO area" ),
            UninitializedRegion( dst=0xDF000000, size=0x01000000, acl="rwx-", name="TCM?" ),
                    DummyRegion( dst=0xE0000000, size=0x8000000, acl="r-x-", name="ROM0"),
                    DummyRegion( dst=0xE8000000, size=0x8000000, acl="r---", name="ROM0_MIRROR"),
                    DummyRegion( dst=0xF0000000, size=0x8000000, acl="r---", name="ROM1"),
                    DummyRegion( dst=0xF8000000, size=0x8000000, acl="r---", name="ROM1_MIRROR")
        )
    )
}


devices = [
    Device(
        model = "80D",
        cpu = cpus["DIGIC6"],
        memSize = 0x40000000,   # 1GB
        firmwares = [
            Firmware(
                version = "1.0.3",
                roms = RegionList(
                    RomRegion( name="ROM1", file="ROM1", dst=0xfe000000, size=0x2000000, module="DryOS" )   # 32MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xff0050a8, dst=       0x0, size=    0x2bf8, module="DryOS", name="ATCM"),
                    ByteMappedRegion( src=0xff011950, dst=    0x4000, size=   0x15f14, module="DryOS", name="kernel"),
                    ByteMappedRegion( src=0xff007ca0, dst=0x80000800, size=    0x9cb0, module="DryOS", name="BTCM"),
                    ByteMappedRegion( src=0xfe000000, dst=0xfc000000, size=      0x48, module="Bootloader", name="EarlyBoot", comment="just the code that jumps into 0xFE...")
                ),
                subregions = RegionList(
                    SubRegion( dst=0xff260000, size= 0x40000, acl="r---", module="DryOS/Data", name="Ring",     comment="via RomRead_task / SaveRingToFile" ),
                    SubRegion( dst=0xff2a0000, size= 0x40000, acl="r---", module="DryOS/Data", name="Custom",   comment="via RomRead_task / SaveCustomToFile" ),
                    SubRegion( dst=0xff2e0000, size= 0xc0000, acl="r---", module="DryOS/Data", name="Rasen",    comment="via RomRead_task / SaveRasenToFile" ),
                    SubRegion( dst=0xff3a0000, size= 0x60000, acl="r---", module="DryOS/Data", name="Lens",     comment="via RomRead_task / SaveLensToFile" ),
                    SubRegion( dst=0xff400000, size= 0x20000, acl="r---", module="DryOS/Data", name="Lens2",    comment="via RomRead_task / string LENS_DATA2_ADDR" ),
                    SubRegion( dst=0xff420000, size= 0x20000, acl="r---", module="DryOS/Data", name="CigData",  comment="via startupPrepareDevelop / string CIG_DATA_ADDR" ),
                    SubRegion( dst=0xff440000, size= 0x20000, acl="r---", module="DryOS/Data", name="Unknown1", comment="via update record +0x08, record size is 0x2A4" ),
                    SubRegion( dst=0xff460000, size=0x160000, acl="r---", module="DryOS/Data", name="Fix",      comment="via RomRead_task" ),
                    SubRegion( dst=0xff820000, size=0x740000, acl="r---", module="DryOS/Data", name="GUI",      comment="via startupPreparePlayback / after string pHeapAddressForWinSys. Size via update record - 0x56c7d8" ),
                    SubRegion( dst=0xfff60000, size= 0x40000, acl="r---", module="DryOS/Data", name="Debug",    comment="via ReadDebugDataFromFROM"),
                    #SubRegion( dst=0xfffa0000, size=     0x8, acl="r---", module="DryOS/Data", name="Unknown2", comment="via dcsChangeAckCBR?"),
                    SubRegion( dst=0xfffe0000, size= 0x20000, acl="r---", module="DryOS/Data", name="PROPAD",  comment="via PROPAD_Initialize params")
                ),
                blobs = {
                    "OMAR": RegionList(
                        # See 0xfe0dbc7c OmarLoader(). ARM blobs.
                        ByteMappedRegion( src=0xfe89b274, dst= 0x01ac0000, size=    0xade8, module="Blobs/OMAR" ),
                        ByteMappedRegion( src=0xfe8a6064, dst= 0x01ae0000, size=  0x2898f0, module="Blobs/OMAR" ),
                        ByteMappedRegion( src=0xfe88890c, dst= 0xdff00000, size=    0x4700, module="Blobs/OMAR" ),
                        ByteMappedRegion( src=0xfe88d014, dst= 0xdff40800, size=    0xe258, module="Blobs/OMAR" )
                    ),
                    "ZICO": RegionList(
                        # See 0xfe0f51d4 ZicoKick(). Xtensa blobs.
                        ByteMappedRegion( src=0xfeb9e5f4, dst= 0x82000000, size=  0x116628, module="Blobs/ZICO" ),
                        ByteMappedRegion( src=0xfeb99b1c, dst= 0xbff00000, size=    0x4ad0, module="Blobs/ZICO" ),
                        ByteMappedRegion( src=0xfeb92094, dst= 0xbff20000, size=    0x7a80, module="Blobs/ZICO" )
                    )
                    # TODO: Arima/Shirahama blob is missing
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xfe020000, dst=       0x0, size=       0x40, acl="rwx-", module="Bootloader", name="reset_vector", overlay=True, clear=False),
                        ByteMappedRegion( src=0xfe0259b4, dst=0x40100000, size=     0xc890, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            ),
        ]
    ),
    Device(
        model = "77D",
        cpu = cpus["DIGIC7"],
        memSize = 0x40000000,   # 1GB
        firmwares = [
            Firmware(
                version = "1.1.0",
                roms = RegionList(
                    RomRegion( name="ROM0", file="ROM0", dst=0xE0000000, size=0x2000000, module="DryOS" ),     # 32MB
                    RomRegion( name="ROM1", file="ROM1", dst=0xF0000000, size=0x1000000, module="DryOS/Data" ) # 16MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xe1189908, dst=    0x4000, size=   0x690c0, module="DryOS", name="ram_code"),
                    ByteMappedRegion( src=0xe11f29c8, dst=0xdf002800, size=    0xce14, module="DryOS", name="TCM")
                ),
                subregions = RegionList(
                    # bootable ends at 0xe1800000
                    SubRegion( dst=0xe1dc0000, size=   0x40000, acl="r---", module="DryOS/Data", name="Ring",   comment="via SaveRingToFile" ),
                    SubRegion( dst=0xe1e00000, size=   0x40000, acl="r---", module="DryOS/Data", name="Custom", comment="via SaveCustomToFile" ),
                    SubRegion( dst=0xe1e40000, size=   0xc0000, acl="r---", module="DryOS/Data", name="Rasen",  comment="via SaveRasenToFile" ),
                    SubRegion( dst=0xe1f00000, size=   0x20000, acl="r---", module="DryOS/Data", name="Lens",   comment="via SaveLensToFile" ),
                    SubRegion( dst=0xe1f20000, size=   0x20000, acl="r---", module="DryOS/Data", name="LENS2",  comment="via SaveLens2ToFile" ),
                    SubRegion( dst=0xe1f60000, size=   0x10000, acl="r---", module="DryOS/Data", name="ppp",    comment="via SavePPPToFile" ),
                    SubRegion( dst=0xe1f70000, size=   0x80000, acl="r---", module="DryOS/Data", name="Debug",  comment="via ReadDebugDataFromFROM" ),
                    SubRegion( dst=0xf0010000, size=  0x820000, acl="r---", module="DryOS/Data", name="GUI",    comment="via SaveGUIToFile" ),
                    SubRegion( dst=0xf0890000, size=  0x320000, acl="r---", module="DryOS/Data", name="Tune",   comment="via SaveTuneToFile" ),
                    SubRegion( dst=0xf0bb0000, size=  0x320000, acl="r---", module="DryOS/Data", name="Tun2",   comment="via SaveTune2ToFile")
                ),
                blobs = {
                    "ZICO": RegionList(
                        # See e0065d42, calls ZicoKick(). Xtensa blobs.
                        ByteMappedRegion( src=0xe0aebe94, dst=0x82000000 , size=  0xf0d80, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe0ae7c2c, dst=0xbff00000 , size=   0x4260, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe0ae2d0c, dst=0xbff20000 , size=   0x4f18, module="Blobs/ZICO"  )
                    ),
                    "LIME": RegionList(
                        # See e00af84c, via 'Async LimeLoader' string. Xtensa blobs.
                        ByteMappedRegion( src=0xe0e26d5c, dst= 0x1a00000, size=   0xa30a8, module="Blobs/LIME"  ),
                        ByteMappedRegion( src=0xe0cbc688, dst= 0x1d00000, size=  0x16a6d0, module="Blobs/LIME"  )
                    )
                    # TODO: Arima/Shirahama blob is missing
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xe00079C0, dst=0xdf000000, size=     0x100, acl="rwx-", module="Bootloader", name="boot1", overlay=True, clear=True),
                        ByteMappedRegion( src=0xe0007764, dst=0xdf020000, size=     0x25C, acl="rwx-", module="Bootloader", name="boot1", overlay=True, clear=True),
                        ByteMappedRegion( src=0xe0010000, dst=0x40100000, size=    0x8E0C, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            ),
        ]
    ),
    Device(
        model = "750D",
        cpu = cpus["DIGIC6"],
        memSize = 0x20000000,   # 512MB
        firmwares = [
            Firmware(
                version = "1.1.0",
                roms = RegionList(
                    RomRegion( name="ROM1", file="ROM1", dst=0xfe000000, size=0x2000000, module="DryOS" )   # 32MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xfed58b7c, dst=       0x0, size=     0x3d4c, module="DryOS", name= "ATCM" ),
                    ByteMappedRegion( src=0xfed652e8, dst=    0x4000, size=    0x363a0, module="DryOS", name= "kernel"),
                    ByteMappedRegion( src=0xfed5c8c8, dst=0x80000800, size=     0x8a20, module="DryOS", name= "BTCM" ),
                    ByteMappedRegion( src=0xfe000000, dst=0xfc000000, size=       0x48, module="Bootloader", name="EarlyBoot", comment="just the code that jumps into 0xFE...")
                ),
                subregions = RegionList(
                    # TODO: fill
                ),
                blobs = {
                    "OMAR": RegionList(
                        # See 0xfe0d8374 OmarLoader(). ARM blobs.
                        ByteMappedRegion( src=0xfe757300, dst=0x01ac0000, size=     0xb060, module="Blobs/OMAR" ),
                        ByteMappedRegion( src=0xfe762368, dst=0x01ae0000, size=   0x2a41c0, module="Blobs/OMAR" ),
                        ByteMappedRegion( src=0xfe744d60, dst=0xdff00000, size=     0x2e78, module="Blobs/OMAR" ),
                        ByteMappedRegion( src=0xfe747be0, dst=0xdff40800, size=     0xf718, module="Blobs/OMAR" )
                    ),
                    "ZICO": RegionList(
                        # See 0xfc1f4544 ZicoKick(). Xtensa blobs.
                        ByteMappedRegion( src=0xfec07610, dst=0x82000000, size=   0x10f8c8, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xfec02b68, dst=0xbff00000, size=     0x4aa0, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xfebfb1e8, dst=0xbff20000, size=     0x7978, module="Blobs/ZICO"  )
                    )
                    # TODO: Arima/Shirahama blob is missing
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xfe020000, dst=       0x0, size=       0x40, acl="rwx-", module="Bootloader", name="reset_vector", overlay=True, clear=False),
                        ByteMappedRegion( src=0xfe026450, dst=0x40100000, size=     0xe500, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            )
        ]
    ),
    Device(
        model = "R",
        cpu = cpus["DIGIC8"],
        memSize = 0x80000000,   # 2GB
        
        firmwares = [
            Firmware(
                version = "1.8.0_7.3.9",
                roms = RegionList(
                    RomRegion( name="ROM0", file="ROM0", dst=0xE0000000, size=0x2000000, module="DryOS" ),     # 32MB
                    RomRegion( name="ROM1", file="ROM1", dst=0xF0000000, size=0x4000000, module="DryOS/Data" ) # 64MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xe12c4294, dst=    0x4000, size=   0x23028, module="DryOS", name="ram_code1"),
                    ByteMappedRegion( src=0xe12e72bc, dst= 0x223b000, size=   0xDA4B0, module="DryOS", name="ram_code2"),
                    ByteMappedRegion( src=0xe13c176c, dst=0xdf002800, size=     0xb20, module="DryOS", name="TCM")
                ),
                subregions = RegionList(
                    # Most of evprocs are registered in e01ad324() late in _init_task_2()
                    SubRegion( dst=0xe0000000,   size=0x40000, acl="rwx-", module="Bootloader", name="boot1",      comment="Bootloader" ),
                    SubRegion( dst=0xe0040000, size=0x1680000, acl="rwx-", module="DryOS",      name="DryOS_code", comment="via CheckSumOfProgramArea" ),
                    # e16c0000 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xe1710000, size=  0x10000, acl="r---", module="DryOS/Data", name="TuneMap",    comment="via CheckSumOfTuneDataMap" ),
                    SubRegion( dst=0xe1720000, size= 0x460000, acl="r---", module="DryOS/Data", name="Tune2a",     comment="via CheckSumOfTuneData2" ),
                    # e1b80000 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xe1bd0000, size=  0x10000, acl="r---", module="DryOS/Data", name="Tune4",      comment="via CheckSumOfTuneData4" ),
                    SubRegion( dst=0xe1be0000, size=  0x80000, acl="r---", module="DryOS/Data", name="Ring",       comment="via CheckSumOfRingData" ),
                    SubRegion( dst=0xe1c60000, size= 0x1c0000, acl="r---", module="DryOS/Data", name="Fix",        comment="via CheckSumOfFixData" ),
                    # e1e20000 - seems unused, no xrefs, 0xFF all the way
                    # e1ec0000 - some data until e1dbf308, no xrefs
                    # e1dbf308 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xe1e70000, size=  0x40000, acl="r---", module="DryOS/Data", name="Debug1",     comment="via SaveDebug1ToFileROM" ),
                    SubRegion( dst=0xe1eb0000, size=  0x40000, acl="r---", module="DryOS/Data", name="Debug2",     comment="via SaveDebug2ToFileROM" ),
                    # e1ef0000 - some data until e1f347a8, just start address xref'd in function called from USBDS
                    # e1f347a8 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xe1f50000, size=  0xa0000, acl="r---", module="DryOS/Data", name="Camif",      comment="via CheckSumOfCamif" ),
                    # e1ff0000 - seems unused, no xrefs, 0xFF all the way
                    # e1ff8000 - bootflags
                    # e1ff9000 - WRITEADJUSTMENTDATATOFROM
                    # e1ffa000 - starts with version from FACT_ICUVersionCheck
                    # e1ffb000 - xref'd in FROMUTIL, AA55AA55 signature
                    # e1ffb100, size = 0x140 - DRAM Param settings
                    # e1ffb240 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xe1ffc000, size=   0x2000, acl="r---", module="DryOS/Data", name="Service",    comment="via SaveServiceToFile" ),
                    SubRegion( dst=0xe1ffe000, size=   0x2000, acl="r---", module="DryOS/Data", name="Error",      comment="via SaveErrorToFile" ),
                    # ROM1
                    SubRegion( dst=0xf0040000, size= 0x180000, acl="r---", module="DryOS/Data", name="Tune2b",     comment="via CheckSumOfTuneData2" ),
                    # f01c0000 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xf04c0000, size= 0x340000, acl="r---", module="DryOS/Data", name="Tune",       comment="via CheckSumOfTuneData" ),
                    SubRegion( dst=0xf0800000, size= 0x1c0000, acl="r---", module="DryOS/Data", name="Tune3",      comment="via SaveTune3ToFile" ),
                    SubRegion( dst=0xf09c0000, size=  0xc0000, acl="r---", module="DryOS/Data", name="Rasen",      comment="via CheckSumOfRasenData" ),
                    SubRegion( dst=0xf0a80000, size=  0x40000, acl="r---", module="DryOS/Data", name="Lens",       comment="via CheckSumOfLensData" ),
                    SubRegion( dst=0xf0ac0000, size=  0x40000, acl="r---", module="DryOS/Data", name="Lens2",      comment="via CheckSumOfLensData2" ),
                    SubRegion( dst=0xf0b00000, size=  0x40000, acl="r---", module="DryOS/Data", name="CigData",    comment="via fn with string CIG_DATA_ADDR" ),
                    SubRegion( dst=0xf0b40000, size= 0x800000, acl="r---", module="DryOS/Data", name="GUI",        comment="via CheckSumOfGUIResource")
                ),
                blobs = {
                    "ZICO": RegionList(
                        # See e008b86e, calls ZicoKick(). Xtensa blobs.
                        ByteMappedRegion( src=0xe0de4c8c, dst=0x80000000, size=   0xe7030, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe0ddf424, dst=0xbff00000, size=    0x5860, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe0dd70e4, dst=0xbff20000, size=    0x8338, module="Blobs/ZICO"  )
                    ),
                    "LIME": RegionList(
                        # See e01ce6c6, via 'Async LimeLoader' string, LimeKick.c. Xtensa blobs.
                        ByteMappedRegion( src=0xe0b50848, dst= 0x1800000, size=  0x177858, module="Blobs/LIME"  ),
                        ByteMappedRegion( src=0xe0cc80a4, dst= 0x1bc0000, size=  0x10d2b0, module="Blobs/LIME"  )
                    ),
                    "SITTER": RegionList(
                        # See e0581e26, called from SitterInit. Xtensa blobs.
                        # I don't see destination in the code. We remove blob anyway.
                        ByteMappedRegion( src=0xe0ecfcdc, dst=       0x0, size=   0x45530, module="Blobs/SITTER"  )
                    ),
                    "ARIMA": RegionList(
                        # Via e0060568(). Function seems a dead end (not called by any code). Xtensa blobs.
                        ByteMappedRegion( src=0xe1271fc8, dst=0x821a1000, size=   0x372E0, module="Blobs/ARIMA"  ),
                        ByteMappedRegion( src=0xe1271e28, dst=0xbf800000, size=     0x198, module="Blobs/ARIMA"  ),
                        # via e0005b18() CamIF_initialize(). Xtensa blobs. Exactly the same blobs as above.
                        # Those are actually used by the camera on boot, from boot1
                        ByteMappedRegion( src=0xe1f501d0, dst=0x821a1000, size=   0x372E0, module="Blobs/ARIMA"  ),
                        ByteMappedRegion( src=0xe1f50030, dst=0xbf800000, size=     0x198, module="Blobs/ARIMA"  )
                    ),
                    "SHIRAHAMA": RegionList(
                        # Via e008bccc(). Function seems a dead end (not called by any code). Xtensa blobs
                        ByteMappedRegion( src=0xe12a9440, dst=0x8220d000, size=   0x1AD08, module="Blobs/SHIRAHAMA"  ),
                        ByteMappedRegion( src=0xe12a92b0, dst=0xbf800400, size=     0x188, module="Blobs/SHIRAHAMA"  ),
                        # via e0005b18() CamIF_initialize(). Xtensa blobs. Exactly the same blobs as above.
                        # Those are actually used by the camera on boot, from boot1
                        ByteMappedRegion( src=0xe1f87640, dst=0x8220d000, size=   0x1AD08, module="Blobs/SHIRAHAMA"  ),
                        ByteMappedRegion( src=0xbf800400, dst=0xbf800400, size=     0x188, module="Blobs/SHIRAHAMA"  )
                    ),
                },
                overlays = {
                
                #another romcpy ?
                #ROM:E001D28A 17 48                       LDR             R0, =sub_E001E000
                #ROM:E001D28C 17 49                       LDR             R1, =0xDF000900
                #ROM:E001D28E 18 4A                       LDR             R2, =0xDF003144
                
                #ROM:E001D2DC A0 47                       BLX             R4               
                
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xe00088ac, dst=0xdf000000, size=     0x100, acl="rwx-", module="Bootloader", name="vector_base", overlay=True), #E0004996
                        ByteMappedRegion( src=0xe0008420, dst=0xdf001000, size=     0x48C, acl="rwx-", module="Bootloader", name="irq_excep_stack_start", overlay=True), #see E00067B4. IRQ exception stack end (PU0)
                        ByteMappedRegion( src=0xe00089c8, dst=0x40100000, size=   0x111820, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True) #see E0007D68. then zeroed until 0x401139D8
                    )
                }
            )
        ]
    ),
       Device(
        model = "R6",
        cpu = cpus["DIGICX"],
        memSize = 0x7F000000-0x40000000,   # 2GB (visible by ICU)
        
        #entry at sub_E0068B44+1
        
        #0xDED02000 : E-FUSES 1 and 2
        
        firmwares = [
            Firmware(
                version = "1.8.2_5.3.7", #Apr 19 2023 08:50:16
                roms = RegionList(
                    RomRegion( name="ROM0", file="ROM0", dst=0xE0000000, size=0x4000000, module="DryOS" ),     # 64MB gang100.bin, SaveAllTuneToFile
                    RomRegion( name="ROM1", file="ROM1", dst=0xF0000000, size=0x2000000, module="DryOS/Data" ) # 32MB gang200.bin
                ),
                                
                romcpy = RegionList(
                    ByteMappedRegion( src=0xE1FBE740, dst=    0x4000, size=   0x3F9DC-0x4000, module="DryOS", name="kernel?"), #E010002C
                    ByteMappedRegion( src=0xE1FFA11C, dst=   0x3F9DC, size=   0xFA5D4-0x3F9DC, module="DryOS", name="ram_code2"), #E0100040. zeroed: 0xFA5D4 -> 0x18F894
                    ByteMappedRegion( src=0xE0000000, dst=0xDFFC0000, size=   0x4900, module="DryOS", name="TranslationTable"), #see E0068BE8
                    #0xDFFC4A00 see below
                    #0xDFFC4B00
                    ByteMappedRegion( src=0xE0082D80, dst=0xDFFC5000, size=   0xE008318C-0xE0082D80, module="DryOS", name="irq_excep_stack_start"), #see E000B2B6, IRQ exception stack start (PU0)
                    #0xDFFC6000 : IRQ exception stack end (PU0) / IRQ exception stack start (PU1)
                    #0xDFFC7000 : IRQ exception stack end (PU1)
                    ByteMappedRegion( src=0xE2039D44, dst=0xDFFC7000, size=   0xDFFC954C-0xDFFC7000, module="DryOS", name="TCM?") #E0100076, then zeroed until 0xDFFC9558

                ),
                #https://wiki.magiclantern.fm/cams:r6
                
                subregions = RegionList(
                    SubRegion( dst=0xe0000000, size= 0x100000, acl="rwx-", module="Bootloader", name="BRCBind",      comment="brcbind" ), #boot,recovery,cipher
                    SubRegion( dst=0xe0100000, size= 0x24C0000, acl="rwx-", module="DryOS",      name="bootable", comment="SaveBootableToFile" ), #ends at 0xE25C0000
                    SubRegion( dst=0xe2600000, size=0x100000, acl="r---", module="DryOS/Data",      name="Duran_Main", comment="" ), #ROM:E1001E9C
                    SubRegion( dst=0xe2700000, size=0x100000, acl="r---", module="DryOS/Data",      name="Duran_Sub", comment="" ), #ROM:E1001EF4
                    SubRegion( dst=0xe2800000, size=0xA80000, acl="r---", module="DryOS/Data",      name="Tune2", comment="SaveTune2ToFile" ), #ends at E328 0000
                    SubRegion( dst=0xe34c0000, size=0x900000, acl="r---", module="DryOS/Data",      name="GUIResource", comment="SaveGUIToFile" ),
                    SubRegion( dst=0xE3E00000, size= 0x40000, acl="r---", module="DryOS/Data",      name="TuneDataMap", comment="TuneDataMap" ),
                    SubRegion( dst=0xe3e40000, size=0x140000, acl="r---", module="DryOS/Data",      name="CamifBin", comment="SaveCamifToFile" ),
                    #E3FF8000 : bootflags
                    SubRegion( dst=0xE3FFC000, size=  0x2000, acl="r---", module="DryOS/Data",      name="Service", comment="SaveServiceToFile" ),

                    SubRegion( dst=0xF0000000, size=  0x1000, acl="r---", module="DryOS/Data",      name="SFInfo", comment=" " ), #ends at 0xf0001000
                    SubRegion( dst=0xF0040000, size=0x200000, acl="r---", module="DryOS/Data",      name="tune2", comment="SaveTune2ToFile" ),    
                    SubRegion( dst=0xF0300000, size=0x300000, acl="r---", module="DryOS/Data",      name="TuneData", comment="TuneData" ),    
                    SubRegion( dst=0xF06C0000, size= 0x40000, acl="r---", module="DryOS/Data",      name="TuneData4", comment="TuneData4" ),    
                    SubRegion( dst=0xf0700000, size= 0xC0000, acl="r---", module="DryOS/Data",      name="FixData", comment=" " ),
                    SubRegion( dst=0xF07C0000, size= 0x80000, acl="r---", module="DryOS/Data",      name="LensData", comment=" " ),
                    SubRegion( dst=0xF0840000, size= 0x40000, acl="r---", module="DryOS/Data",      name="LensData2", comment=" " ),
                    SubRegion( dst=0xF0880000, size=0x280000, acl="r---", module="DryOS/Data",      name="LensData3", comment=" " ),
                    SubRegion( dst=0xF0B00000,size=0x1000000, acl="r---", module="DryOS/Data",      name="LensData4", comment=" " ),
                    SubRegion( dst=0xF1B00000, size= 0xC0000, acl="r---", module="DryOS/Data",      name="LensData5", comment=" " ),
                    SubRegion( dst=0xF1BC0000, size= 0xC0000, acl="r---", module="DryOS/Data",      name="PictStyle", comment=" " ),
                    SubRegion( dst=0xF1C80000, size= 0x80000, acl="r---", module="DryOS/Data",      name="RingData", comment=" " ),
                    SubRegion( dst=0xF1D00000, size= 0xC0000, acl="r---", module="DryOS/Data",      name="RasenData", comment=" " ),
                    SubRegion( dst=0xF1DC0000, size= 0x80000, acl="r---", module="DryOS/Data",      name="CustomData", comment=" " ),
                    SubRegion( dst=0xF1E80000, size=0x100000, acl="r---", module="DryOS/Data",      name="unk", comment=" " ),

                    SubRegion( dst=0xf1f80000, size=0x40000, acl="r---", module="DryOS/Data",      name="Debug1", comment="SaveDebug1ToFileROM" ),
                    SubRegion( dst=0xf1fc0000, size=0x40000, acl="r---", module="DryOS/Data",      name="Debug2", comment="SaveDebug2ToFileROM" )

                ),
                #?ROM:E1001F70 dword_E1001F70  DCD 0xD2210180          ; DATA XREF: sub_E01F6870+3A?o
                
                blobs = {
                    # each blob is preceded with destination (uint32) and size (uint32), then [blob data]
                    "ZICO": RegionList(
                        # See ROM:E04559DA, "ZicoKick/ZicoKick.c". Xtensa blobs.
                        ByteMappedRegion( src=0xE1A46A50, dst=0x80000000, size=   0x80308, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xE1A40740, dst=0xbff00000, size=    0x6308, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xE1A39200, dst=0xbff20000, size=    0x7538, module="Blobs/ZICO"  )
                    ),
                    # table at ROM:E0AD1ED8 with 2 32bits entries [ num, dest, source, addr of size ] num =0 for end of table
                    "LIME": RegionList( 

                    ),
                    "SITTER": RegionList( 

                    ),
                    "ARIMA": RegionList( 

                    ),
                    "SHIRAHAMA": RegionList( 

                    ),
                },
                overlays = {
                
                #ROM:E02FE2E0 : exception vector
                #0x18F89B : Error exception stack start (PU0)
                #0xDFFC5000 : IRQ exception stack start (PU0)
                #0xDFFC6000 : IRQ exception stack end (PU0) / IRQ exception stack start (PU1)
                #0xDFFC7000 : IRQ exception stack end (PU1)
                
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
 
                        ByteMappedRegion( src=0xE0068CE8, dst=0xDFFC4A00, size= 0xE0068D8C-0xE0068CE8, acl="rwx-", module="Bootloader", name="unk2", overlay=True),
                        ByteMappedRegion( src=0xE0068AFC, dst=0xDFFC4B00, size= 0xE0068B30-0xE0068AFC, acl="rwx-", module="Bootloader", name="unk3", overlay=True) #then BLX  0xDFFC4B01
                        
                        
                        
                    )
                }
            )
        ]
    )

]
