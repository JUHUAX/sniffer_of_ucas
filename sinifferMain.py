import sys
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMenu, QMessageBox
from PyQt5.QtCore import *
from snifferUI import Ui_Form
from selectNIC import getNIC
import forIP
from capture import capturePacket, readcurPacket, allPacket, clearAll
from scapy.all import hexdump
from fileop import savePcpFile, readPcpFile
from tracePacket import traceIPandPort
import dpkt
import time

class snifferMain(QMainWindow, Ui_Form):
    packetCountSingnl = pyqtSignal(list)
    updateProtocolListSingnl = pyqtSignal(list)
    updateProtocolListByLastRowSingnl = pyqtSignal(dict)
    updateShowLayerAndBinarySingnl = pyqtSignal(dict, dict, dict, dict)
    def __init__(self, parent=None):
        super(snifferMain, self).__init__(parent)
        self.setupUi(self)
        self.showNIC()
        self.curNIC = ""
        self.selectNIC.currentIndexChanged.connect(self.changeNIC)
        self.startButtonValue = False
        self.startButton.clicked.connect(self.setStartButton)
        self.stopButtonValue = False
        self.stopButton.clicked.connect(self.setStopButton)
        self.protocolTable.itemClicked.connect(self.choosePacket)
        self.packetCountSingnl.connect(self.updateCount)
        self.updateProtocolListSingnl.connect(self.updateProtocolList)
        self.updateProtocolListByLastRowSingnl.connect(self.updateProtocolListByLastRow)
        self.updateShowLayerAndBinarySingnl.connect(self.updateShowLayerAndBinary)
        self.outputButton.clicked.connect(self.outPutPacket)
        self.importButton.clicked.connect(self.importPacket)
        self.protocolTable.customContextMenuRequested.connect(self.generateMenu)
        
    
    def generateMenu(self,pos):
        rowNum = 0
        for i in self.protocolTable.selectionModel().selection().indexes():
            rowNum = i.row()
        menu = QMenu()
        item = menu.addAction(u"追踪")
        action = menu.exec_(self.protocolTable.mapToGlobal(pos))
        if action == item:
            self.trace(rowNum)
        else:
            return
        
    
    def trace(self, index):
        traceAns = traceIPandPort(index)
        if traceAns == False:
            msg_box = QMessageBox(QMessageBox.Critical, '错误', '你选择的并不是tcp或udp报文')
            msg_box.exec_()
            return
        self.updateProtocolListSingnl.emit(traceAns)
        
    def updateProtocolList(self, packet):
        self.protocolTable.setRowCount(0)
        for i in range(len(packet)):
            data = forIP.analysisIP(packet[i].data)
            self.protocolTable.setRowCount(i + 1)
            newItem=QTableWidgetItem(str(data["src"]))
            self.protocolTable.setItem(i,0,newItem)
            newItem=QTableWidgetItem(str(data["dst"]))
            self.protocolTable.setItem(i,1,newItem)
            newItem=QTableWidgetItem(str(data["protocol"]))
            self.protocolTable.setItem(i,2,newItem)
            newItem=QTableWidgetItem(str(data["len"]))
            self.protocolTable.setItem(i,3,newItem)
            self.protocolTable.scrollToBottom()
            QApplication.processEvents()
    
    
    
    def outPutPacket(self):
        savePcpFile()
    
    def importPacket(self):
        readPcpFile()
        packet = allPacket()
        self.protocolTable.setRowCount(0)
        for i in range(len(packet)):
            self.updateProtocolListByLastRowSingnl.emit(packet[i])
            
    
    def choosePacket(self, item=None):
        if item == None:
            return
        else:
            row = item.row()
            col = item.column()
            self.analysisChoosePacket([row, col])
    
    def updateShowLayerAndBinary(self, ethLayer, ipLayer, transLayer, applyLayer):
        QApplication.processEvents()
        _translate = QCoreApplication.translate
        self.showBinary.setText(hexdump(ethLayer["data"], dump=True))
        self.showLayers.topLevelItem(0).setText(0, _translate("Form", "链路层数据"))
        self.showLayers.topLevelItem(0).child(0).setText(0, _translate("Form", "源MAC地址：" + ethLayer["src"] ))
        self.showLayers.topLevelItem(0).child(1).setText(0, _translate("Form", "目的MAC地址：" + ethLayer["dst"]))
        if ethLayer["type"] == "arp":
            self.showLayers.topLevelItem(1).setText(0, _translate("Form", "ARP数据"))
            self.showLayers.topLevelItem(1).child(0).setText(0, _translate("Form", "版本：" + ipLayer["protocol"]))
            self.showLayers.topLevelItem(1).child(1).setText(0, _translate("Form", "源MAC：" + ipLayer["src"]))
            self.showLayers.topLevelItem(1).child(2).setText(0, _translate("Form", "目的MAC：" + ipLayer["dst"]))
            self.showLayers.topLevelItem(1).child(4).setText(0, _translate("Form", "长度：" + str(ipLayer["len"])))
        else:
            self.showLayers.topLevelItem(1).setText(0, _translate("Form", "IP层数据"))
            self.showLayers.topLevelItem(1).child(0).setText(0, _translate("Form", "版本：" + ipLayer["protocol"]))
            self.showLayers.topLevelItem(1).child(1).setText(0, _translate("Form", "源IP：" + ipLayer["src"]))
            self.showLayers.topLevelItem(1).child(2).setText(0, _translate("Form", "目的IP：" + ipLayer["dst"]))
            self.showLayers.topLevelItem(1).child(3).setText(0, _translate("Form", "上层协议：" + ipLayer["upprotocol"]))
            self.showLayers.topLevelItem(1).child(4).setText(0, _translate("Form", "长度：" + str(ipLayer["len"])))
            self.showLayers.topLevelItem(2).setText(0, _translate("Form", "运输层数据"))
            if transLayer["protocol"] == "tcp":
                self.showLayers.topLevelItem(2).child(0).setText(0, _translate("Form", "协议类型：" + "tcp"))
                self.showLayers.topLevelItem(2).child(1).setText(0, _translate("Form", "源端口号：" + str(transLayer["sport"])))
                self.showLayers.topLevelItem(2).child(2).setText(0, _translate("Form", "目的端口号：" + str(transLayer["dport"])))
                self.showLayers.topLevelItem(2).child(3).setText(0, _translate("Form", "校验和:" + str(transLayer["sum"])))
                if applyLayer != {} and applyLayer["protocol"] == "http":
                    self.showLayers.topLevelItem(3).setText(0, _translate("Form", "应用层数据"))
                    self.showLayers.topLevelItem(3).child(0).setText(0, _translate("Form", "协议类型：" + "http"))
                    if applyLayer["type"] == "request":
                        self.showLayers.topLevelItem(3).child(1).setText(0, _translate("Form", "方法：" + str(applyLayer["method"])))
                        self.showLayers.topLevelItem(3).child(2).setText(0, _translate("Form", "版本：" + str(applyLayer["version"])))
                        self.showLayers.topLevelItem(3).child(3).setText(0, _translate("Form", "URL:" + str(applyLayer["url"])))
                    elif applyLayer["type"] == "response":
                        self.showLayers.topLevelItem(3).child(1).setText(0, _translate("Form", "版本：" + str(applyLayer["version"])))
                        self.showLayers.topLevelItem(3).child(2).setText(0, _translate("Form", "状态：" + str(applyLayer["status"])))
                        self.showLayers.topLevelItem(3).child(3).setText(0, _translate("Form", "reason:" + str(applyLayer["reason"])))
                if applyLayer != {} and applyLayer["protocol"] == "dns":
                    self.showLayers.topLevelItem(3).setText(0, _translate("Form", "应用层数据"))
                    self.showLayers.topLevelItem(3).child(0).setText(0, _translate("Form", "协议类型：" + "dns"))
                    if applyLayer["type"] == "request":
                        self.showLayers.topLevelItem(3).child(1).setText(0, _translate("Form", "op：" + str(applyLayer["op"])))
                        self.showLayers.topLevelItem(3).child(2).setText(0, _translate("Form", "qd：" + str(applyLayer["qd"])))
                        self.showLayers.topLevelItem(3).child(3).setText(0, _translate("Form", "an:" + str(applyLayer["aa"])))
            elif transLayer["protocol"] == "udp":
                self.showLayers.topLevelItem(2).child(0).setText(0, _translate("Form", "协议类型：" + "udp"))
                self.showLayers.topLevelItem(2).child(1).setText(0, _translate("Form", "源端口号：" + str(transLayer["sport"])))
                self.showLayers.topLevelItem(2).child(2).setText(0, _translate("Form", "目的端口号：" + str(transLayer["dport"])))
                self.showLayers.topLevelItem(2).child(3).setText(0, _translate("Form", "长度" + str(transLayer["ulen"])))
            elif transLayer["protocol"] == "icmp":
                self.showLayers.topLevelItem(2).child(0).setText(0, _translate("Form", "协议类型：" + "icmp"))
                self.showLayers.topLevelItem(2).child(1).setText(0, _translate("Form", "code：" + str(transLayer["code"])))
                self.showLayers.topLevelItem(2).child(2).setText(0, _translate("Form", "校验和：" + str(transLayer["sum"])))
                self.showLayers.topLevelItem(2).child(3).setText(0, _translate("Form", "类型：" + str(transLayer["type"]) ))
            elif transLayer["protocol"] == "icmp6":
                self.showLayers.topLevelItem(2).child(0).setText(0, _translate("Form", "协议类型：" + "icmp6"))
                self.showLayers.topLevelItem(2).child(1).setText(0, _translate("Form", "code：" + str(transLayer["code"])))
                self.showLayers.topLevelItem(2).child(2).setText(0, _translate("Form", "校验和：" + str(transLayer["sum"])))
                self.showLayers.topLevelItem(2).child(3).setText(0, _translate("Form", "类型：" + str(transLayer["type"]) ))
    
    def analysisChoosePacket(self, pos):
        analysisResult = readcurPacket(pos[0])
        ethLayer = analysisResult["ethLayer"]
        if ethLayer["type"] == "arp":
            ipLayer = analysisResult["ARP"]
            transLayer = {}
            applyLayer = {}
        else:
            ipLayer = analysisResult["ipLayer"]
            transLayer = analysisResult["transLayer"]
            applyLayer = analysisResult["applyLayer"]
        
        self.updateShowLayerAndBinarySingnl.emit(ethLayer, ipLayer, transLayer, applyLayer)
        
        
        
    def showNIC(self):
        self.nic = getNIC("all")
        self.selectNIC.addItems(self.nic)
    
    def changeNIC(self):
        self.curNIC = self.selectNIC.currentText().split(":")[1]
        print(self.curNIC)
    
    def setStartButton(self):
        self.startButtonValue = True
        self.stopButtonValue = False
        f = self.inputRules.text()
        self.captureProtocolPacket(f)
    
    def setStopButton(self):
        self.stopButtonValue = True
        self.startButtonValue = False
        # self.analysis.join()
        
    def updateProtocolListByLastRow(self, data):
        if isinstance(data["ethLayer"]["data"], dpkt.arp.ARP):
            packet = data["ARP"]
            tmp = "ARP"
        else:
            packet = data["ipLayer"]
            if data["applyLayer"] != {}:
                tmp = data["applyLayer"]["protocol"]
            else:
                tmp = packet["upprotocol"]
        count = self.protocolTable.rowCount()
        self.protocolTable.insertRow(count)
        newItem=QTableWidgetItem(str(packet["src"]))
        self.protocolTable.setItem(count,0,newItem)
        newItem=QTableWidgetItem(str(packet["dst"]))
        self.protocolTable.setItem(count,1,newItem)
        newItem=QTableWidgetItem(str(tmp))
        self.protocolTable.setItem(count,2,newItem)
        newItem=QTableWidgetItem(str(packet["len"]))
        self.protocolTable.setItem(count,3,newItem)
        self.protocolTable.scrollToBottom()
        QApplication.processEvents()
    
    def analysisPacket(self):
        packet = {}
        count = 0
        http_sum = 0
        tcp_sum = 0
        udp_sum = 0
        icmp_sum = 0
        ip_sum = 0
        arp_sum = 0
        dns_sum = 0
        self.protocolTable.setRowCount(0)
        while self.startButtonValue :
            time.sleep(0.0001)
            packet = readcurPacket(count)
            if packet == -1:
                continue
            self.updateProtocolListByLastRowSingnl.emit(packet)
            if len(packet.keys()) == 2:
                arp_sum += 1
            else:
                ip_sum += 1
                if packet["ipLayer"]["upprotocol"] == "UDP":
                    udp_sum += 1
                elif packet["ipLayer"]["upprotocol"] == "TCP":
                    tcp_sum += 1
                    if packet["applyLayer"] != {} and packet["applyLayer"]["protocol"] == "http":
                        http_sum += 1
                    if packet["applyLayer"] != {} and packet["applyLayer"]["protocol"] == "dns":
                        dns_sum += 1
                else:
                    icmp_sum += 1
            count += 1
            self.packetCountSingnl.emit([http_sum,tcp_sum, udp_sum, icmp_sum, ip_sum, arp_sum ,count, dns_sum])
    
    
    def updateCount(self,l):
        self.httpProtocol.setText(str(l[0]))
        self.tcpProtocol.setText(str(l[1]))
        self.udpProtocol.setText(str(l[2]))
        self.icmpProtocol.setText(str(l[3]))
        self.ipProtocol.setText(str(l[4]))
        self.arpProtocol.setText(str(l[5]))
        self.protocolSum.setText(str(l[6]))
        self.dnsProtocol.setText(str(l[7]))
    
    
    def capture(self, f):
        capturePacket(self.curNIC, f)
        while 1:
            if self.startButtonValue == False:
                return
    
    def captureProtocolPacket(self, f):
        self.protocolList = threading.Thread(target=self.capture, kwargs={"f": f})
        self.protocolList.start()
        self.analysis = threading.Thread(target=self.analysisPacket)
        self.analysis.start()
            
        

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = snifferMain()
    sniffer.show()
    sys.exit(app.exec())

