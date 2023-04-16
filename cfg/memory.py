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
            UninitializedRegion( dst=0xC0000000, size= 0x2000000, acl="rw-v", name="MMIO 0xC0000000" ),
            UninitializedRegion( dst=0xC4000000, size= 0x1000000, acl="rw-v", name="MMIO 0xC4000000" ),
            UninitializedRegion( dst=0xC8000000, size= 0x2000000, acl="rw-v", name="MMIO 0xC8000000" ),
            UninitializedRegion( dst=0xD0000000, size= 0x1000000, acl="rw-v", name="MMIO 0xD0000000" ),
            UninitializedRegion( dst=0xD2000000, size= 0x1000000, acl="rw-v", name="MMIO 0xD2000000" ),
            UninitializedRegion( dst=0xD4000000, size= 0x2000000, acl="rw-v", name="MMIO 0xD4000000" ),
            UninitializedRegion( dst=0xD8000000, size= 0x2000000, acl="rw-v", name="MMIO 0xD8000000" ),
            UninitializedRegion( dst=0xDE000000, size= 0x1000000, acl="rw-v", name="MMIO 0xDE000000" ),
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
            UninitializedRegion( dst=0xC0000000, size= 0x3000000, acl="rw-v", name="MMIO 0xC0000000" ),
            UninitializedRegion( dst=0xC4000000, size= 0x1000000, acl="rw-v", name="MMIO 0xC4000000" ),
            UninitializedRegion( dst=0xC8000000, size= 0x2000000, acl="rw-v", name="MMIO 0xC8000000" ),
            UninitializedRegion( dst=0xCC000000, size= 0x2000000, acl="rw-v", name="MMIO 0xCC000000" ),
            UninitializedRegion( dst=0xD0000000, size= 0x1000000, acl="rw-v", name="MMIO 0xD0000000" ),
            UninitializedRegion( dst=0xD2000000, size= 0x1000000, acl="rw-v", name="MMIO 0xD2000000" ),
            UninitializedRegion( dst=0xD4000000, size= 0x2000000, acl="rw-v", name="MMIO 0xD4000000" ),
            UninitializedRegion( dst=0xD7000000, size= 0x3000000, acl="rw-v", name="MMIO 0xD7000000" ),
            UninitializedRegion( dst=0xDE000000, size= 0x1000000, acl="rw-v", name="MMIO 0xDE000000" ),
            UninitializedRegion( dst=0xDF000000, size= 0x1000000, acl="rwx-", name="TCM" ),
                    DummyRegion( dst=0xE0000000, size= 0x8000000, acl="r-x-", name="ROM0"),
                    DummyRegion( dst=0xE8000000, size= 0x8000000, acl="r---", name="?" ),
                    DummyRegion( dst=0xF0000000, size= 0x8000000, acl="r---", name="ROM1"),
                    DummyRegion( dst=0xF8000000, size= 0x8000000, acl="r---", name="?" )
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
                    RomRegion( name="ROM1", file="ROM1", dst=0xfe000000, size=0x2000000 )   # 32MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xff0050a8, dst=       0x0, size=    0x2bf8, name="ATCM"),
                    ByteMappedRegion( src=0xff011950, dst=    0x4000, size=   0x15f14, name="DryOS"),
                    ByteMappedRegion( src=0xff007ca0, dst=0x80000800, size=    0x9cb0, name="BTCM"),
                    ByteMappedRegion( src=0xfe000000, dst=0xfc000000, size=      0x48, name="Boot", comment="just the code that jumps into 0xFE...")
                ),
                subregions = RegionList(
                    SubRegion( dst=0xff260000, size= 0x40000, acl="r---", name="Ring",    comment="via RomRead_task / SaveRingToFile" ),
                    SubRegion( dst=0xff2a0000, size= 0x40000, acl="r---", name="Custom",  comment="via RomRead_task / SaveCustomToFile" ),
                    SubRegion( dst=0xff2e0000, size= 0xc0000, acl="r---", name="Rasen",   comment="via RomRead_task / SaveRasenToFile" ),
                    SubRegion( dst=0xff3a0000, size= 0x60000, acl="r---", name="Lens",    comment="via RomRead_task / SaveLensToFile" ),
                    SubRegion( dst=0xff400000, size= 0x20000, acl="r---", name="Lens2",   comment="via RomRead_task / string LENS_DATA2_ADDR" ),
                    SubRegion( dst=0xff420000, size= 0x20000, acl="r---", name="CigData", comment="via startupPrepareDevelop / string CIG_DATA_ADDR" ),
                    SubRegion( dst=0xff460000, size=0x160000, acl="r---", name="Fix",     comment="via RomRead_task" ),
                    SubRegion( dst=0xff820000, size=     0x8, acl="r---", name="GUI",     comment="via startupPreparePlayback / after string pHeapAddressForWinSys" ),
                    SubRegion( dst=0xfff60000, size= 0x40000, acl="r---", name="Debug",   comment="via ReadDebugDataFromFROM"),
                    #SubRegion( dst=0xfffa0000, size=     0x8, acl="r---", name="Unknown", comment="via dcsChangeAckCBR?"),
                    SubRegion( dst=0xfffe0000, size= 0x20000, acl="r---", name="PROPAD",  comment="via PROPAD_Initialize params")
                ),
                blobs = {
                    "OMAR": RegionList(
                        # See 0xfe0dbc7c OmarLoader()
                        ByteMappedRegion( src=0xfe89b274, dst= 0x01ac0000, size=    0xade8 ),
                        ByteMappedRegion( src=0xfe8a6064, dst= 0x01ae0000, size=  0x2898f0 ),
                        ByteMappedRegion( src=0xfe88890c, dst= 0xdff00000, size=    0x4700 ),
                        ByteMappedRegion( src=0xfe88d014, dst= 0xdff40800, size=    0xe258 )
                    ),
                    "ZICO": RegionList(
                        # See 0xfe0f51d4 ZicoKick()
                        ByteMappedRegion( src=0xfeb9e5f4, dst= 0x82000000, size=  0x116628 ),
                        ByteMappedRegion( src=0xfeb99b1c, dst= 0xbff00000, size=    0x4ad0 ),
                        ByteMappedRegion( src=0xfeb92094, dst= 0xbff20000, size=    0x7a80 )
                    )
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xfe020000, dst=       0x0, size=       0x40, acl="rwx-", name="reset_vector", overlay=True, clear=False),
                        ByteMappedRegion( src=0xfe0259b4, dst=0x40100000, size=     0xc890, acl="rwx-", name="FROMUTIL", overlay=True)
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
                    RomRegion( name="ROM0", file="ROM0", dst=0xE0000000, size=0x2000000 ),  # 32MB
                    RomRegion( name="ROM1", file="ROM1", dst=0xF0000000, size=0x1000000 )   # 16MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xe1189908, dst=    0x4000, size=   0x690c0, name="DryOS"),
                    ByteMappedRegion( src=0xe11f29c8, dst=0xdf002800, size=    0xce14, name="TCM")
                ),
                subregions = RegionList(
                    # bootable ends at 0xe1800000
                    SubRegion( dst=0xe1dc0000, size=   0x40000, acl="r---", name="Ring",   comment="via SaveRingToFile" ),
                    SubRegion( dst=0xe1e00000, size=   0x40000, acl="r---", name="Custom", comment="via SaveCustomToFile" ),
                    SubRegion( dst=0xe1e40000, size=   0xc0000, acl="r---", name="Rasen",  comment="via SaveRasenToFile" ),
                    SubRegion( dst=0xe1f00000, size=   0x20000, acl="r---", name="Lens",   comment="via SaveLensToFile" ),
                    SubRegion( dst=0xe1f20000, size=   0x20000, acl="r---", name="LENS2",  comment="via SaveLens2ToFile" ),
                    SubRegion( dst=0xe1f60000, size=   0x10000, acl="r---", name="ppp",    comment="via SavePPPToFile" ),
                    SubRegion( dst=0xe1f70000, size=   0x80000, acl="r---", name="Debug",  comment="via ReadDebugDataFromFROM" ),
                    SubRegion( dst=0xf0010000, size=  0x820000, acl="r---", name="GUI",    comment="via SaveGUIToFile" ),
                    SubRegion( dst=0xf0890000, size=  0x320000, acl="r---", name="Tune",   comment="via SaveTuneToFile" ),
                    SubRegion( dst=0xf0bb0000, size=  0x320000, acl="r---", name="Tun2",   comment="via SaveTune2ToFile")
                ),
                blobs = {
                    "ZICO": RegionList(
                        # See e0065d42, calls ZicoKick(
                        ByteMappedRegion( src=0xe0aebe94, dst=0x82000000 , size=  0xf0d80 ),
                        ByteMappedRegion( src=0xe0ae7c2c, dst=0xbff00000 , size=   0x4260 ),
                        ByteMappedRegion( src=0xe0ae2d0c, dst=0xbff20000 , size=   0x4f18 )
                    ),
                    "LIME": RegionList(
                        # See e00af84c, via 'Async LimeLoader' string
                        ByteMappedRegion( src=0xe0e26d5c, dst= 0x1a00000, size=   0xa30a8 ),
                        ByteMappedRegion( src=0xe0cbc688, dst= 0x1d00000, size=  0x16a6d0 )
                    )
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xe00079C0, dst=0xdf000000, size=     0x100, acl="rwx-", name="boot1", overlay=True, clear=True),
                        ByteMappedRegion( src=0xe0007764, dst=0xdf020000, size=     0x25C, acl="rwx-", name="boot1", overlay=True, clear=True),
                        ByteMappedRegion( src=0xe0010000, dst=0x40100000, size=    0x8E0C, acl="rwx-", name="FROMUTIL", overlay=True)
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
                    RomRegion( name="ROM1", file="ROM1", dst=0xfe000000, size=0x2000000 )   # 32MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xfed58b7c, dst=       0x0, size=     0x3d4c, name= "ATCM" ),
                    ByteMappedRegion( src=0xfed652e8, dst=    0x4000, size=    0x363a0, name= "DryOS"),
                    ByteMappedRegion( src=0xfed5c8c8, dst=0x80000800, size=     0x8a20, name= "BTCM" ),
                    ByteMappedRegion( src=0xfe000000, dst=0xfc000000, size=       0x48, name= "Boot", comment="just the code that jumps into 0xFE...")
                ),
                subregions = RegionList(
                    # TODO: fill
                ),
                blobs = {
                    "OMAR": RegionList(
                        # See 0xfe0d8374 OmarLoader()
                        ByteMappedRegion( src=0xfe757300, dst=0x01ac0000, size=     0xb060 ),
                        ByteMappedRegion( src=0xfe762368, dst=0x01ae0000, size=   0x2a41c0 ),
                        ByteMappedRegion( src=0xfe744d60, dst=0xdff00000, size=     0x2e78 ),
                        ByteMappedRegion( src=0xfe747be0, dst=0xdff40800, size=     0xf718 )
                    ),
                    "ZICO": RegionList(
                        # See 0xfc1f4544 ZicoKick()
                        ByteMappedRegion( src=0xfec07610, dst=0x82000000, size=   0x10f8c8 ),
                        ByteMappedRegion( src=0xfec02b68, dst=0xbff00000, size=     0x4aa0 ),
                        ByteMappedRegion( src=0xfebfb1e8, dst=0xbff20000, size=     0x7978 )
                    )
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xfe020000, dst=       0x0, size=       0x40, acl="rwx-", name="reset_vector", overlay=True, clear=False),
                        ByteMappedRegion( src=0xfe026450, dst=0x40100000, size=     0xe500, acl="rwx-", name="FROMUTIL", overlay=True)
                    )
                }
            )
        ]
    )
]
