# `LoadROM.py` and `TestMemoryMapGenerator.py`

Load ROM files and populate memory map.

## How to use?

### Create a project

Open a Code Browser window, either by opening any existing file in your project,
or by clicking "Code browser" button in "Tool Chest" of Project window.

Run `LoadROM.py` from Script manager. When asked, select your camera
model and firmware version. Then provide ROM files. 

If everything goes right, a new, read only file will be open in CodeBrowser
window.

In `Program Trees` section, click on a little 'folder' icon on the right.
Select `EOS` to open a structured program tree.

Use `Save As` to save the file in your project.

### Test / validate configuration change in `cfg/memory.py`

If you modified `cfg/memory.py` either to update existing or add a new model,
run `TestMemoryMapGenerator.py` to validate a config. It works exactly like
`LoadROM.py`, except it doesn't create actual project - only prints generated
memory map (and any errors) in scripting console.

## Syntax of `cfg/memory.py`, or "how can I contribute to a memory map?"

This will make a lot more sense if you open `cfg/memory.py` and follow the 
descriptions. Data clases are implemented in `mlLib/MemTable.py`.

Configuration is split into two sections: `cpus` and `devices`.

### `cpus` - description of specific ICU

Each entry in `cpus` dictionary should be and object of `CPU` class.

`CPU` class defines ICU architecture, compiler type and a "base" map of memory
regions - more on that later.

### `devices` - list of devices, firmwares and firmware specific regions
Each entry in `devices` list should be an object of `Device` class.

`Device` class defines model name, CPU from `cpus` dict, size of memory and
a list of `Firmware` objects for that model.

### `Firmware` class
Firmware describes a specific version of a specific model firmware.

It contains a few sections:
- `roms`: list of ROM files to load
- `romcpy`: list of ROM-to-RAM data copies that go into main memory space
- `subregions`: ability to split big memory regions into small ones, with own name, ACLs, etc...
- `blobs`: Dict of lists of firmware blobs for other cores. They will be erased from project for a better analysis
- `overlays`: Dict of lists of ROM-to-RAM data copies that are loaded as "overlays"

### Region types

#### `DummyRegion`
Just a placeholder area used in `CPU` definitions for ROM and RAM areas.

Everything that's not taken by any of `Firmware` regions will be ommited from the project.

#### `UninitializedRegion`
Memory area filled with `uninitialized bytes`. 

#### `RomRegion`
Memory region that directly references a file bytes (from a ROM dump).

### `ByteMappedRegion`
Memory region that contains bytes of another region already loaded into memory map (usually `RomRegion`)

### `SubRegion`
Memory region that is split from existing, bigger memory region under its own name and permissions.

## How memory map is generated from config file?

For code see `mlLib/MemoryMap.py`

### Base table
1. Create empty memory map
2. Insert all entries from `CPU` config, as a base map.

### Firmware table
1. Create empty memory map
2. Create actual RAM regions (`UninitializedRegion`)
3. Create regions for ROM files (`rom` list)
4. Create rom copy regions (`romcpy` list)

### Device table
1. Merge Firmware table into Base table
2. Create subregions (`subregions` list)
3. Remove any firmware blobs (unless defined with clear=False), (`blobs` dict)
4. Remove any rom copy source regions (unless defined with clear=False), (`romcpy` list)
5. Remove any leftover `DummyRegion` regions
6. Add any overlays, and clear source regions (unless defined with clear=False), (`overlays` dict)
