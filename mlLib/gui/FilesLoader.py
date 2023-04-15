from mlLib.toolbox import getFileProvider

def loadFilesError():
    from docking.widgets import OptionDialogBuilder
    title = "ROM files load error"
    msg = "One or more files failed to load. Unable to continue"
    dialog = OptionDialogBuilder(title, msg)
    dialog.show()

    
def askFileError(name, reason):
    from docking.widgets import OptionDialogBuilder
    title = "Load failed: {}".format(name)
    msg = "Unable to load file {} due to a following reason:\n{}\nRetry?".format(name,reason)
    dialog = OptionDialogBuilder(title, msg)
    dialog.addOption("Retry")
    dialog.addOption("Abort")
    val = dialog.show()
    if val == 1:
        return True

    return False
    
def loadFile(rom):
    from java.awt import KeyboardFocusManager
    import java.io
    from docking.widgets.filechooser import GhidraFileChooser

    kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    window = kfm.getActiveWindow()
    
    name = rom.name
    size = rom.getSize()
    msg = ""
    
    fc = GhidraFileChooser(window)
    fc.setTitle(name)
    f = fc.getSelectedFile()
    
    if isinstance(f, java.io.File):
        if f.length() != size:
            msg = "Size doesn't match: Expected 0x{:08x}, got 0x{:08x}".format(
                    size, f.length())
            print msg
            return (False, msg)
        return (f, msg)

    msg = "Not a file."
    print msg
    return (False, msg)
        
def loadFiles(roms):
    files = {}
    for rom in roms:
        f, message = loadFile(rom)
        print(message)
        while not f:
            if askFileError(rom.name, message):
                f, message = loadFile(rom)
                print(message)
            else:
                return

        provider = getFileProvider(f.getAbsolutePath(), rom.name)

        files[rom.name] = provider
            
    return files