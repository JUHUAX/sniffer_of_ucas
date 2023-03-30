import dpkt
from PyQt5.QtWidgets import QFileDialog 
from capture import allPacketRaw, sendPacket


def savePcpFile():
    filename, filter_index = QFileDialog.getSaveFileName()
    if filename == "":
        return
    data = allPacketRaw()
    with open(filename, 'wb') as f:
        writer = dpkt.pcap.Writer(f)
        for i in range(len(data)):
            writer.writepkt(data[i])
            
def readPcpFile():
    filename, filter_index= QFileDialog.getOpenFileName()
    if filename == "":
        return
    data = []
    with open(filename, 'rb') as f:
        reader = dpkt.pcap.Reader(f)
        for ts, pkt in reader.readpkts():
            data.append(pkt)
    sendPacket(data)