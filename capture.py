from winpcapy import WinPcapUtils
from foreth import analysisARP, analysisEth
from forIP import analysisIP
from forTransport import analysisTrans
from forapply import analysisApply
import dpkt

curPacketRaw = []
curPacket = []

def capturePacket(device_name, filter):
    global curPacket
    global curPacketRaw
    curPacketRaw = []
    curPacket = []
    if filter == "":
        WinPcapUtils.capture_on_device_name(device_name=device_name, callback=ethernetCallback)
    else:
        WinPcapUtils.compile_and_capture_on_device_name(device_name=device_name, packet_filter=bytes(filter, encoding='utf-8'), callback=ethernetCallback)



def ethernetCallback(win_pcap, param, header, pkt_data):
    global curPacket
    eth = dpkt.ethernet.Ethernet(pkt_data)
    curPacketRaw.append(eth)
    packet = analyCurPacket(eth)
    curPacket.append(packet)

def readcurPacket(index):
    global curPacket
    if(index >= len(curPacket)):
        return -1
    return curPacket[index]

def allPacketRaw():
    global curPacketRaw
    return curPacketRaw

def allPacket():
    global curPacket
    return curPacket

def sendPacket(data):
    global curPacket
    global curPacketRaw
    curPacket = []
    curPacketRaw = []
    for i in range(len(data)):
        curPacketRaw.append(dpkt.ethernet.Ethernet(data[i]))
        curPacket.append(analyCurPacket(dpkt.ethernet.Ethernet(data[i])))

def analyCurPacket(data):
    ethLayerPacket = analysisEth(data)
    if ethLayerPacket["type"] == "arp":
        return {"ethLayer": ethLayerPacket,
            "ARP":analysisARP(ethLayerPacket["data"])
            }
    ipLayerPacket = analysisIP(ethLayerPacket["data"])
    transLayerPacket = {}
    transLayerPacket = analysisTrans(ipLayerPacket["data"])
    # if (transLayerPacket["sport"] == 80 or transLayerPacket["sport"] == 53):
    #     print("http or dns!!!!")
    #     print(str(transLayerPacket["data"], encoding="utf-8"))
    if transLayerPacket == {}:
        applyLayerPacket = {}
    else:
        applyLayerPacket = analysisApply(transLayerPacket["data"])
    return {"ethLayer": ethLayerPacket,
            "ipLayer": ipLayerPacket,
            "transLayer": transLayerPacket,
            "applyLayer":applyLayerPacket
            }
    
def clearAll():
    global curPacket
    global curPacketRaw
    curPacketRaw.clear()
    curPacket.clear()
# capturePacket("\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}")