from __main__ import askChoice

def selectFirmware(devices):
    try:
        device = askChoice("Select device", "Please choose a device from the list:", devices, None)
        fw = askChoice("Select firmware", "{} firmwares:".format(device.model), device.firmwares, None)
        return (device, fw)
    except:
        print("User cancelled selection")
        exit(1)
