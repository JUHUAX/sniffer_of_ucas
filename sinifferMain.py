import sys
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem
from snifferUI import Ui_Form
from selectNIC import getNIC
from forIP import forIP, readcurPacket

class snifferMain(QMainWindow, Ui_Form):
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
        while self.startButtonValue :
            tmp = readcurPacket()
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
            count += 1
    
    def showProtocolList(self):
        # protocolList = threading.Thread(target=forIP, kwargs={"device_name": "\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}"})
        protocolList = threading.Thread(target=forIP, kwargs={"device_name": self.curNIC})
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

