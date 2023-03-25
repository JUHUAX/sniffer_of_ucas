import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
from snifferUI import Ui_Form
from selectNIC import getNIC
from forIP import IP

class snifferMain(QMainWindow, Ui_Form):
    def __init__(self, parent=None):
        super(snifferMain, self).__init__(parent)
        self.setupUi(self)
        self.showNIC()
        self.curNIC = ""
        self.selectNIC.currentIndexChanged.connect(self.changeNIC)
        self.showProtocolList()
        
    def showNIC(self):
        self.nic = getNIC("all")
        self.selectNIC.addItems(self.nic)
    
    def changeNIC(self):
        self.curNIC = self.selectNIC.currentText()
    
    def showProtocolList(self):
        ip = IP(self.curNIC).forIP(self.curNIC)
        print(ip)
        

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = snifferMain()
    sniffer.show()
    sys.exit(app.exec())