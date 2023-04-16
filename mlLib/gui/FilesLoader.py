import java.io
from __main__ import askYesNo, askFile
from mlLib.toolbox import getFileProvider

def loadFilesError():
    from docking.widgets import OptionDialogBuilder
    title = "ROM files load error"
    msg = "One or more files failed to load. Unable to continue"
    OptionDialogBuilder(title, msg).show()


def askOnLoadError(name, reason):
    title = "Load failed: {}".format(name)
    msg = "Unable to load file {} due to a following reason:\n{}\nRetry?".format(name,reason)
    return askYesNo(title, msg)


def loadFile(title, rom, size):
    msg = "OK"
    f = None
    try:
        f = askFile(title,"Select")
    except:
        msg = "File selection cancelled."
        return (False, msg)

    if f.length() != size:
        msg = "Size doesn't match: Expected 0x{:08x}, got 0x{:08x}".format(
                size, f.length())
        print msg
        return (False, msg)

    return (f, msg)


def loadFiles(device, fw):
    files = {}
    for rom in fw.roms:
        size = rom.getSize()
        title = "{}_{}: {} (expected size: 0x{:08x})".format(device.model, fw.version, rom.name, size)

        f = None
        while not f:
            f, message = loadFile(title, rom, size)
            if not f and not askOnLoadError(rom.name, message):
                return
        files[rom.name] = getFileProvider(f.getAbsolutePath(), rom.name)

    return files
