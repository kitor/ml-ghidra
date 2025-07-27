from mlLib.MemTable import *

cpus = {
    "DIGIC5": CPU(
        # https://foss.heptapod.net/magic-lantern/magic-lantern/-/blob/branch/qemu/contrib/qemu/eos/model_list.c#L257
        # Cameras may have ROM0, will have ROM1 at 0xF8000000.
        # Roms are mirrored with + 0x100000 increments (0xF9.. 0xFF...)
        # Code executes from 0xFF... so not to make things harder only this address is loaded to Ghidra
        arch = "ARM",
        lang = "ARM:LE:32:v5",
        compiler = "default",
        regions = RegionList(
            UninitializedRegion( dst=       0x0, size=    0x1000, acl="rwx-", name="ATCM"),
                    DummyRegion( dst=    0x1000, size=0x3FFFF000, acl="rwx-", name="RAM CACHED"),
                    DummyRegion( dst=0x40000000, size=0x40000000, acl="rwx-", name="RAM UNCACHED"),
            UninitializedRegion( dst=0xC0000000, size=0x20000000, acl="rw-v", name="MMIO"),
                    DummyRegion( dst=0xF0000000, size= 0x1000000, acl="r---", name="ROM0"),
                    DummyRegion( dst=0xF8000000, size= 0x1000000, acl="r-x-", name="ROM1_MIRROR"),
                    DummyRegion( dst=0xFF000000, size= 0x1000000, acl="r-x-", name="ROM1")
        )
    ),
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
    )
}


devices = [
    Device(
        model = "70D",
        cpu = cpus["DIGIC5"],
        memSize = 0x20000000,   # 512MB
        firmwares = [
            Firmware(
                version = "1.1.2",
                roms = RegionList(
                    RomRegion( name="ROM0", file="ROM0", dst=0xf0000000, size=0x1000000, module="DryOS/Data" ),  # 16MB
                    RomRegion( name="ROM1", file="ROM1", dst=0xff000000, size=0x1000000, module="DryOS" )   # 16MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xff0c0da0, dst=       0x0, size=      0x38, module="DryOS",      name="ATCM1"),
                    ByteMappedRegion( src=0xff0c0dd8, dst=     0x4B0, size=     0x1E8, module="DryOS",      name="ATCM2"),
                    ByteMappedRegion( src=0xffd4ce18, dst=    0x1900, size=   0xAD5C4, module="DryOS",      name="Code"),
                    ByteMappedRegion( src=0xff0c0000, dst=0xf80c0000, size=     0x100, module="Bootloader",  name="EarlyBoot", clear=False, comment="just the code that jumps into 0xF")
                ),
                subregions = RegionList(
                    # Tune, TuneForSlave - properties? List is likely incomplete
                    SubRegion( dst=0xf0020000, size= 0x40000, acl="r---", module="DryOS/Data", name="Custom",     comment="via SaveCustomToFile" ),
                    SubRegion( dst=0xf0060000, size= 0x60000, acl="r---", module="DryOS/Data", name="Rasen",      comment="via SaveRasenToFile" ),
                    SubRegion( dst=0xf00c0000, size=0x100000, acl="r---", module="DryOS/Data", name="Fix",        comment="via SaveFixToFile" ),
                    # 0xf01e0000, 0x20000?
                    SubRegion( dst=0xf01e0000, size= 0x60000, acl="r---", module="DryOS/Data", name="Lens",       comment="via SaveLensToFile" ),

                    SubRegion( dst=0xf0700000, size= 0x20000, acl="r---", module="DryOS/Data", name="PROPAD",     comment="via PROPAD_Initialize params"),
                    SubRegion( dst=0xf0740000, size= 0x20000, acl="r---", module="DryOS/Data", name="CigData",    comment="via startupPrepareDevelop / string CIG_DATA_ADDR" ),
                    SubRegion( dst=0xf07a0000, size= 0x40000, acl="r---", module="DryOS/Data", name="Debug",      comment="via ReadDebugDataFromFROM"),
                    # Stuff from 0xF8000000 region moved to 0xFF000000
                    SubRegion( dst=0xff080000, size= 0x40000, acl="r---", module="DryOS/Data", name="Ring",       comment="via SaveRingToFile" ),
                    SubRegion( dst=0xff0c0000, size=0xe80000, acl="r-x-", module="DryOS",      name="DryOS_code", comment="via CheckSumOfProgramArea" )
                ),
                blobs = {
                    "EEKO": RegionList(
                        # Via xrefs to ff41aea4 EekoBltDmac(). ARM Thumb2 blobs. Destination locations unknown.
                        ByteMappedRegion( src=0xffc6c6a4, dst=        0x0, size=    0x6e94, module="Blobs/EEKO", comment="via ff5c7998()" ), #0xd0288000
                        ByteMappedRegion( src=0xffc73538, dst=        0x0, size=     0x1c0, module="Blobs/EEKO", comment="via ff5c79fc()" ), #0xd0280000
                        ByteMappedRegion( src=0xffc736f8, dst=        0x0, size=    0x1db8, module="Blobs/EEKO", comment="via ff5c79fc()" )  #0x01ec0000
                    ),
                },
                overlays = {
                    "boot1": RegionList(
                        ByteMappedRegion( src=0xfffe0000, dst=  0x100000, size=     0xFFDC, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            ),
        ]
    ),
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
                    SubRegion( dst=0xe0000000,   size=0x40000, acl="r-x-", module="Bootloader", name="boot1",      comment="Bootloader" ),
                    SubRegion( dst=0xe0040000, size=0x1680000, acl="r-x-", module="DryOS",      name="DryOS_code", comment="via CheckSumOfProgramArea" ),
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
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xe00088ac, dst=0xdf000000, size=     0x100, acl="rwx-", module="Bootloader", name="boot1_exception_stack", overlay=True),
                        ByteMappedRegion( src=0xe0008420, dst=0xdf001000, size=     0x48C, acl="rwx-", module="Bootloader", name="boot1_0xdf001000", overlay=True),
                        ByteMappedRegion( src=0xe00089c8, dst=0x40100000, size=   0x11820, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            )
        ]
    ),
    Device(
        model = "G7X_III",
        cpu = cpus["DIGIC8"],
        memSize = 0x40000000,   # 2GB
        firmwares = [
            Firmware(
                version = "1.3.2_4.0.0",
                roms = RegionList(
                    RomRegion( name="ROM0", file="ROM0", dst=0xE0000000, size=0x2000000, module="DryOS" ),     # 32MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xe105a50c, dst=    0x4000, size=   0x25738, module="DryOS", name="ram_code1"),
                    ByteMappedRegion( src=0xe107fc44, dst= 0x223b000, size=  0x10DBCC, module="DryOS", name="ram_code2"),
                    ByteMappedRegion( src=0xe118d810, dst=0xdf002800, size=     0xB94, module="DryOS", name="TCM")
                ),
                subregions = RegionList(
                    # Most of evprocs are registered in e00bf9b8() late in _init_task_2()
                    SubRegion( dst=0xe0000000,   size=0x40000, acl="r-x-", module="Bootloader", name="boot1",      comment="Bootloader" ),
                    SubRegion( dst=0xe0040000, size=0x1230000, acl="r-x-", module="DryOS",      name="DryOS_code", comment="via CheckSumOfProgramArea" ),
                    SubRegion( dst=0xe1270000, size=  0x20000, acl="r---", module="DryOS/Data", name="Custom",     comment="via SaveCustomToFile" ),
                    SubRegion( dst=0xe1290000, size= 0x5e0000, acl="r---", module="DryOS/Data", name="GUI",        comment="via CheckSumOfGUIResource"),
                    # 0xe1870000 TAGS01_A? there's e03a595e() which returns this address, no xrefs from any functions. Followed by TAGS02_A and TAGS03_A
                    SubRegion( dst=0xe1870000, size=  0x40B00, acl="r---", module="DryOS/Data", name="TAGS01_A",   comment="via header string"),
                    SubRegion( dst=0xe18b0b00, size=  0x3C900, acl="r---", module="DryOS/Data", name="TAGS01_A",   comment="via header string"),
                    SubRegion( dst=0xe18ed400, size=  0xA2C00, acl="r---", module="DryOS/Data", name="TAGS01_A",   comment="via header string"),
                    # end of unknown region
                    #SubRegion( dst=0xe1970000, size=  0x20000, acl="r---", module="DryOS/Data", name="Ring",       comment="via SaveRingToFile" ),
                    SubRegion( dst=0xe1990000, size=  0x60000, acl="r---", module="DryOS/Data", name="Rasen",      comment="via SaveRasenToFile" ),
                    SubRegion( dst=0xe19f0000, size= 0x180000, acl="r---", module="DryOS/Data", name="Fix",        comment="via SaveFixToFile" ),
                    SubRegion( dst=0xe1b70000, size=  0xa0000, acl="r---", module="DryOS/Data", name="Camif",      comment="via SaveCamifToFile" ),
                    SubRegion( dst=0xe1c10000, size=  0x10000, acl="r---", module="DryOS/Data", name="CigData",    comment="via fn with string CIG_DATA_ADDR" ),
                    SubRegion( dst=0xe1c20000, size=  0x30000, acl="r---", module="DryOS/Data", name="Debug1",     comment="via SaveDebug1ToFileROM" ),
                    SubRegion( dst=0xe1c50000, size=  0x30000, acl="r---", module="DryOS/Data", name="Debug2",     comment="via SaveDebug2ToFileROM" ),
                    # 0xe1c80000 - seems empty, 0xFF all the way
                    SubRegion( dst=0xe1ca0000, size= 0x1a0000, acl="r---", module="DryOS/Data", name="Tune",       comment="via SaveTuneToFile" ),
                    SubRegion( dst=0xe1e40000, size= 0x1a0000, acl="r---", module="DryOS/Data", name="Tune3",      comment="via SaveTune2ToFile" ),
                    SubRegion( dst=0xe1fe0000, size=  0x10000, acl="r---", module="DryOS/Data", name="Tune4",      comment="via SaveTune4ToFile" ),
                    # e1ff0000 - seems unused, no xrefs, 0xFF all the way
                    # e1ff8000 - bootflags
                    # e1ff9000 - WRITEADJUSTMENTDATATOFROM
                    # e1ffa000 - starts with version from FACT_ICUVersionCheck
                    # e1ffb000 - xref'd in FROMUTIL, AA55AA55 signature
                    # e1ffb100, size = 0x140 - DRAM Param settings
                    # e1ffb240 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xe1ffc000, size=   0x2000, acl="r---", module="DryOS/Data", name="Service",    comment="via SaveServiceToFile" ),
                    SubRegion( dst=0xe1ffe000, size=   0x2000, acl="r---", module="DryOS/Data", name="Error",      comment="via SaveErrorToFile" )
                ),
                blobs = {
                    "ZICO": RegionList(
                        # See e00c66ee, calls ZicoKick(). Xtensa blobs.
                        ByteMappedRegion( src=0xe0de2960, dst=0x80000000, size=   0xe8c68, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe0ddc7d8, dst=0xbff00000, size=    0x6180, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe0dd4498, dst=0xbff20000, size=    0x8338, module="Blobs/ZICO"  )
                    ),
                    "LIME": RegionList(
                        # See e07d5f8c, via 'Async LimeLoader' string, LimeKick.c. Xtensa blobs.
                        ByteMappedRegion( src=0xe0b0bfe0, dst= 0x1800000, size=  0x1a89f8, module="Blobs/LIME"  ),
                        ByteMappedRegion( src=0xe0cb49dc, dst= 0x1bc0000, size=  0x114230, module="Blobs/LIME"  )
                    ),
                    "SITTER": RegionList(
                        # See e03613ae, called from SitterInit. Xtensa blobs.
                        # I don't see destination in the code. We remove blob anyway.
                        ByteMappedRegion( src=0xe0ecdcfc, dst=       0x0, size=   0x45cc0, module="Blobs/SITTER"  )
                    ),
                    "ARIMA": RegionList(
                        # via e0006924() CamIF_initialize(). Xtensa blobs.
                        ByteMappedRegion( src=0xe1b701c0, dst=0x821a1000, size=    0x8690, module="Blobs/ARIMA"  ),
                        ByteMappedRegion( src=0xe1b70030, dst=0xbf800000, size=     0x190, module="Blobs/ARIMA"  )
                    ),
                    "SHIRAHAMA": RegionList(
                        # via e0006924() CamIF_initialize(). Xtensa blobs.
                        ByteMappedRegion( src=0xe1b789d8, dst=0x8220d000, size=   0x137d8, module="Blobs/SHIRAHAMA"  ),
                        ByteMappedRegion( src=0xe1b78850, dst=0xbf800400, size=     0x188, module="Blobs/SHIRAHAMA"  )
                    ),
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xe00091a0, dst=0xdf000000, size=     0x100, acl="rwx-", module="Bootloader", name="boot1_exception_stack", overlay=True),
                        ByteMappedRegion( src=0xe0008bb8, dst=0xdf001000, size=     0x5E8, acl="rwx-", module="Bootloader", name="boot1_0xdf001000", overlay=True),
                        ByteMappedRegion( src=0xe00092bc, dst=0x40100000, size=   0x12524, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            )
        ]
    ),
    Device(
        model = "M6_II",
        cpu = cpus["DIGIC8"],
        memSize = 0x80000000,   # 2GB
        firmwares = [
            Firmware(
                version = "1.1.1_5.9.2",
                roms = RegionList(
                    RomRegion( name="ROM0", file="ROM0", dst=0xE0000000, size=0x2000000, module="DryOS" ),     # 32MB
                    RomRegion( name="ROM1", file="ROM1", dst=0xF0000000, size=0x1000000, module="DryOS/Data" ) # 16MB
                ),
                romcpy = RegionList(
                    ByteMappedRegion( src=0xe1512200, dst=    0x4000, size=   0x27958, module="DryOS", name="ram_code1"),
                    ByteMappedRegion( src=0xe1539b58, dst= 0x223b000, size=  0x11D3D8, module="DryOS", name="ram_code2"),
                    ByteMappedRegion( src=0xe1656f30, dst=0xdf002800, size=     0xb94, module="DryOS", name="TCM")
                ),
                subregions = RegionList(
                    SubRegion( dst=0xe0000000,   size=0x40000, acl="r-x-", module="Bootloader", name="boot1",      comment="Bootloader" ),
                    SubRegion( dst=0xe0040000, size=0x1670000, acl="r-x-", module="DryOS",      name="DryOS_code", comment="via CheckSumOfProgramArea" ),
                    SubRegion( dst=0xe16b0000, size=  0x40000, acl="r---", module="DryOS/Data", name="Custom",     comment="via SaveCustomToFile" ),
                    SubRegion( dst=0xe16f0000, size=  0x90000, acl="r---", module="DryOS/Data", name="Rasen",      comment="via CheckSumOfRasenData" ),
                    SubRegion( dst=0xe1780000, size=  0x10000, acl="r---", module="DryOS/Data", name="TuneMap",    comment="via CheckSumOfTuneDataMap" ),
                    SubRegion( dst=0xe1790000, size= 0x2f0000, acl="r---", module="DryOS/Data", name="Tune2a",     comment="via CheckSumOfTuneData2" ),
                    SubRegion( dst=0xe1a80000, size= 0x1b0000, acl="r---", module="DryOS/Data", name="Tune1a",     comment="via SaveTuneToFile" ),
                    SubRegion( dst=0xe1c30000, size=  0x10000, acl="r---", module="DryOS/Data", name="Tune4",      comment="via CheckSumOfTuneData4" ),
                    SubRegion( dst=0xe1c40000, size=  0x40000, acl="r---", module="DryOS/Data", name="Ring",       comment="via CheckSumOfRingData" ),
                    SubRegion( dst=0xe1c80000, size=  0x80000, acl="r---", module="DryOS/Data", name="Lens5",      comment="via SaveLens5ToFile" ),
                    SubRegion( dst=0xe1d00000, size= 0x180000, acl="r---", module="DryOS/Data", name="Lens3",      comment="via SaveLens3ToFile" ),
                    SubRegion( dst=0xe1e80000, size=  0x20000, acl="r---", module="DryOS/Data", name="Lens",       comment="via CheckSumOfLensData" ),
                    SubRegion( dst=0xe1ea0000, size=  0x20000, acl="r---", module="DryOS/Data", name="Lens2",      comment="via CheckSumOfLensData2" ),
                    SubRegion( dst=0xe1ec0000, size=  0x10000, acl="r---", module="DryOS/Data", name="CigData",    comment="via fn with string CIG_DATA_ADDR" ),
                    SubRegion( dst=0xe1ed0000, size=  0x40000, acl="r---", module="DryOS/Data", name="Debug1",     comment="via SaveDebug1ToFileROM" ),
                    SubRegion( dst=0xe1f10000, size=  0x40000, acl="r---", module="DryOS/Data", name="Debug2",     comment="via SaveDebug2ToFileROM" ),
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
                    SubRegion( dst=0xf0010000, size= 0x2f0000, acl="r---", module="DryOS/Data", name="Tune2b",     comment="via CheckSumOfTuneData2" ),
                    # F0300000 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xf0380000, size= 0x1b0000, acl="r---", module="DryOS/Data", name="Tune1a",     comment="via SaveTuneToFile" ),
                    # F0530000 - seems unused, no xrefs, 0xFF all the way
                    SubRegion( dst=0xf05a0000, size= 0x190000, acl="r---", module="DryOS/Data", name="Fix",        comment="via CheckSumOfFixData" ),
                    SubRegion( dst=0xf0730000, size= 0x8d0000, acl="r---", module="DryOS/Data", name="GUI",        comment="via CheckSumOfGUIResource")
                ),
                blobs = {
                    "ZICO": RegionList(
                        # See e0185148, calls ZicoKick(). Xtensa blobs.
                        ByteMappedRegion( src=0xe1020710, dst=0x80000000, size=   0xe8c68, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe101a588, dst=0xbff00000, size=    0x6180, module="Blobs/ZICO"  ),
                        ByteMappedRegion( src=0xe1012248, dst=0xbff20000, size=    0x8338, module="Blobs/ZICO"  )
                    ),
                    "LIME": RegionList(
                        # See e03109ac, via 'Async LimeLoader' string, LimeKick.c. Xtensa blobs.
                        ByteMappedRegion( src=0xe0d4c3c4, dst= 0x1800000, size=  0x1a8998, module="Blobs/LIME"  ),
                        ByteMappedRegion( src=0xe0ef4d60, dst= 0x1bc0000, size=  0x111d20, module="Blobs/LIME"  )
                    ),
                    "SITTER": RegionList(
                        # See e02066b6, called from SitterInit. Xtensa blobs.
                        # I don't see destination in the code. We remove blob anyway.
                        ByteMappedRegion( src=0xe11143b8, dst=       0x0, size=   0x45c70, module="Blobs/SITTER"  )
                    ),
                    "ARIMA": RegionList(
                        # via e00069ac() CamIF_initialize(). Xtensa blobs. Exactly the same blobs as above.
                        # Those are actually used by the camera on boot, from boot1
                        ByteMappedRegion( src=0xe1f501c0, dst=0x821a1000, size=   0x2F548, module="Blobs/ARIMA"  ),
                        ByteMappedRegion( src=0xe1f50030, dst=0xbf800000, size=     0x190, module="Blobs/ARIMA"  )
                    ),
                    "SHIRAHAMA": RegionList(
                        # via e00069ac() CamIF_initialize(). Xtensa blobs. Exactly the same blobs as above.
                        # Those are actually used by the camera on boot, from boot1
                        ByteMappedRegion( src=0xe1f7f890, dst=0x8220d000, size=   0x1CEC8, module="Blobs/SHIRAHAMA"  ),
                        ByteMappedRegion( src=0xe1f7f708, dst=0xbf800400, size=     0x188, module="Blobs/SHIRAHAMA"  )
                    ),
                },
                overlays = {
                    "boot1": RegionList(
                        # RAM code for the 1st stage bootloader
                        ByteMappedRegion( src=0xe00091f0, dst=0xdf000000, size=     0x100, acl="rwx-", module="Bootloader", name="boot1_exception_stack", overlay=True),
                        ByteMappedRegion( src=0xe0008c0c, dst=0xdf001000, size=     0x5E4, acl="rwx-", module="Bootloader", name="boot1_0xdf001000", overlay=True),
                        ByteMappedRegion( src=0xe000930c, dst=0x40100000, size=   0x126B0, acl="rwx-", module="Bootloader", name="FROMUTIL", overlay=True)
                    )
                }
            )
        ]
    ),
]
