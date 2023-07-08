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

See [Memory Map](docs/MemoryMap.md) 
