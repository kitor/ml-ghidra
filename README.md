# Ghidra scripts for Magic Lantern development

This repository contains Ghidra scripts that should be helpful while working
with Canon EOS based firmwares.

## Contents

### `LoadROM.py` and `TestMemoryMapGenerator.py`
Python implementation of ROM loader. Loads ROM for selected model, and prepares
a complete memory map based on definitions in `cfg/memory.py`

**For details, see [Load ROM](docs/LoadROM.md)**

### `StateObjects.py` and `StateObjectOneShot.py`
Decode and define data structures from CreateStateObject calls.
Create functions where autoanalysis missed them, optionally - change name
prefixes, set function arg1 to proper name / type and assign function to
a namespace.

**For details, see [State Objects](docs/StateObjects.md)**


## How to use?
Add the root folder of this repository to Script manager:
1. Open CodeBrowser tool.
2. Navigate to Window -> Script manager
3. Click on "Manage scripts directories" button in top-right corner.
4. Add your checked out repository to the list.
5. Scripts will appear in Script Manager, in MagicLantern directory.
