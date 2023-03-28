from winpcapy import WinPcapUtils
from foreth import ethernetCallback



def analysisPcket(device_name):
    WinPcapUtils.capture_on_device_name(device_name=device_name, callback=ethernetCallback)



# analysisPcket("\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}")