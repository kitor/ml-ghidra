# Ghidra scripts for Magic Lantern development

This repository contains Ghidra scripts that should be helpful while working
with Canon EOS based firmwares.

## Contents

### `LoadROM.py` and `TestMemoryMapGenerator.py`
Python implementation of ROM loader. Loads ROM for selected model, and prepares
a complete memory map based on definitions in `cfg/memory.py`

** For details, see [Load ROM](docs/LoadROM.md) **

## How to use?
Add the root folder of this repository to Script manager:
1. Open CodeBrowser tool.
2. Navigate to Window -> Script manager
3. Click on "Manage scripts directories" button in top-right corner.
4. Add your checked out repository to the list.
5. Scripts will appear in Script Manager, in MagicLantern directory.
