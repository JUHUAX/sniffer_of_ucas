from forIP import forIP, readcurPacket
import threading

def askLoop():
    packet = {}
    count = 0
    while 1 :
        tmp = readcurPacket()
        print(tmp)


protocolList = threading.Thread(target=forIP, kwargs={"device_name": "\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}"})
protocolList.start()
ask = threading.Thread(target=askLoop)
ask.start()