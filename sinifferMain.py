import sys
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMenu, QMessageBox
from PyQt5.QtCore import *
from snifferUI import Ui_Form
from selectNIC import getNIC
import forIP
from capture import capturePacket
import foreth
from scapy.all import hexdump
from fileop import savePcpFile, readPcpFile
from tracePacket import traceIPandPort

class snifferMain(QMainWindow, Ui_Form):
    packetCountSingnl = pyqtSignal(list)
    updateProtocolListSingnl = pyqtSignal(list)
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
        self.outputButton.clicked.connect(self.outPutPacket)
        self.importButton.clicked.connect(self.importPacket)
        self.protocolTable.customContextMenuRequested.connect(self.generateMenu)
    
    def generateMenu(self,pos):
        rowNum = 0
        for i in self.protocolTable.selectionModel().selection().indexes():
            rowNum = i.row()
            print(rowNum)
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
            newItem=QTableWidgetItem("待定")
            self.protocolTable.setItem(i,4,newItem)
            self.protocolTable.scrollToBottom()
    
    
    
    def outPutPacket(self):
        savePcpFile()
    
    def importPacket(self):
        readPcpFile()
        packet = foreth.readcurPacket()
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
            newItem=QTableWidgetItem("待定")
            self.protocolTable.setItem(i,4,newItem)
            self.protocolTable.scrollToBottom()
            
    
    def choosePacket(self, item=None):
        if item == None:
            return
        else:
            row = item.row()
            col = item.column()
            self.analysisChoosePacket([row, col])
    
    def analysisChoosePacket(self, pos):
        _translate = QCoreApplication.translate
        analysisResult = foreth.analyCurPacket(pos[0])
        ethLayer = analysisResult["ethLayer"]
        ipLayer = analysisResult["ipLayer"]
        transLayer = analysisResult["transLayer"]
        self.showBinary.setText(hexdump(ethLayer["data"], dump=True))
        self.showLayers.topLevelItem(0).setText(0, _translate("Form", "链路层数据"))
        self.showLayers.topLevelItem(0).child(0).setText(0, _translate("Form", "源MAC地址：" + ethLayer["src"] ))
        self.showLayers.topLevelItem(0).child(1).setText(0, _translate("Form", "目的MAC地址：" + ethLayer["dst"]))
        self.showLayers.topLevelItem(1).setText(0, _translate("Form", "IP层数据"))
        self.showLayers.topLevelItem(1).child(0).setText(0, _translate("Form", "版本：" + ipLayer["protocol"]))
        self.showLayers.topLevelItem(1).child(1).setText(0, _translate("Form", "源IP：" + ipLayer["src"]))
        self.showLayers.topLevelItem(1).child(2).setText(0, _translate("Form", "目的IP：" + ipLayer["dst"]))
        self.showLayers.topLevelItem(1).child(3).setText(0, _translate("Form", "上层协议：" + ipLayer["protocol"]))
        self.showLayers.topLevelItem(1).child(4).setText(0, _translate("Form", "长度：" + str(ipLayer["len"])))
        self.showLayers.topLevelItem(2).setText(0, _translate("Form", "运输层数据"))
        if transLayer["protocol"] == "tcp":
            self.showLayers.topLevelItem(2).child(0).setText(0, _translate("Form", "协议类型：" + "tcp"))
            self.showLayers.topLevelItem(2).child(1).setText(0, _translate("Form", "源端口号：" + str(transLayer["sport"])))
            self.showLayers.topLevelItem(2).child(2).setText(0, _translate("Form", "目的端口号：" + str(transLayer["dport"])))
            self.showLayers.topLevelItem(2).child(3).setText(0, _translate("Form", "校验和:" + str(transLayer["sum"])))
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
        
        
        
    def showNIC(self):
        self.nic = getNIC("all")
        self.selectNIC.addItems(self.nic)
    
    def changeNIC(self):
        self.curNIC = self.selectNIC.currentText().split(":")[1]
        print(self.curNIC)
    
    def setStartButton(self):
        self.startButtonValue = True
        self.stopButtonValue = False
        self.showProtocolList()
    
    def setStopButton(self):
        self.stopButtonValue = True
        self.startButtonValue = False
    
    def askLoop(self):
        packet = {}
        count = 0
        http_sum = 0
        tcp_sum = 0
        udp_sum = 0
        icmp_sum = 0
        ip_sum = 0
        self.protocolTable.setRowCount(0)
        while self.startButtonValue :
            tmp = forIP.readcurPacket()
            if packet == tmp:
                continue
            packet = tmp
            self.protocolTable.setRowCount(count + 1)
            newItem=QTableWidgetItem(str(packet["src"]))
            self.protocolTable.setItem(count,0,newItem)
            newItem=QTableWidgetItem(str(packet["dst"]))
            self.protocolTable.setItem(count,1,newItem)
            newItem=QTableWidgetItem(str(packet["protocol"]))
            self.protocolTable.setItem(count,2,newItem)
            newItem=QTableWidgetItem(str(packet["len"]))
            self.protocolTable.setItem(count,3,newItem)
            newItem=QTableWidgetItem("待定")
            self.protocolTable.setItem(count,4,newItem)
            self.protocolTable.scrollToBottom()
            if packet["protocol"] == "ICMP" or packet["protocol"] == "IPv6-ICMP":
                icmp_sum += 1
            if packet["protocol"] == "TCP":
                tcp_sum += 1
            if packet["protocol"] == "UDP":
                udp_sum += 1
            self.packetCountSingnl.emit([http_sum, tcp_sum, udp_sum, icmp_sum, count])
            
            count += 1
    
    
    def updateCount(self,l):
        self.httpProtocol.setText(str(l[0]))
        self.tcpProtocol.setText(str(l[1]))
        self.udpProtocol.setText(str(l[2]))
        self.icmpProtocol.setText(str(l[3]))
        self.ipProtocol.setText(str(l[4] + 1))
        self.protocolSum.setText(str(l[4] + 1))
    
    
    def showProtocolList(self):
        # protocolList = threading.Thread(target=forIP, kwargs={"device_name": "\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}"})
        protocolList = threading.Thread(target=capturePacket, kwargs={"device_name": self.curNIC})
        protocolList.start()
        ask = threading.Thread(target=self.askLoop)
        ask.start()
        if self.stopButtonValue:
            return
            
        

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = snifferMain()
    sniffer.show()
    sys.exit(app.exec())

