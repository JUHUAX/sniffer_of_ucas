# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\sniffer.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1789, 856)
        self.verticalLayoutWidget = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(50, 60, 141, 91))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label.setObjectName("label")
        self.verticalLayout_3.addWidget(self.label)
        self.label_2 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_3.addWidget(self.label_2)
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(230, 59, 611, 91))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.selectNIC = QtWidgets.QComboBox(self.verticalLayoutWidget_2)
        self.selectNIC.setObjectName("selectNIC")
        self.verticalLayout_4.addWidget(self.selectNIC)
        self.inputRules = QtWidgets.QLineEdit(self.verticalLayoutWidget_2)
        self.inputRules.setText("")
        self.inputRules.setObjectName("inputRules")
        self.verticalLayout_4.addWidget(self.inputRules)
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(50, 170, 1471, 650))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.protocolTable = QtWidgets.QTableWidget(self.verticalLayoutWidget_3)
        self.protocolTable.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.protocolTable.setAcceptDrops(False)
        self.protocolTable.setObjectName("protocolTable")
        self.protocolTable.setColumnCount(4)
        self.protocolTable.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.protocolTable.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.protocolTable.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.protocolTable.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.protocolTable.setHorizontalHeaderItem(3, item)

        self.verticalLayout_5.addWidget(self.protocolTable)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.showLayers = QtWidgets.QTreeWidget(self.verticalLayoutWidget_3)
        self.showLayers.setObjectName("showLayers")
        item_0 = QtWidgets.QTreeWidgetItem(self.showLayers)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_0 = QtWidgets.QTreeWidgetItem(self.showLayers)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_0 = QtWidgets.QTreeWidgetItem(self.showLayers)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_0 = QtWidgets.QTreeWidgetItem(self.showLayers)
        self.horizontalLayout.addWidget(self.showLayers)
        self.showBinary = QtWidgets.QTextBrowser(self.verticalLayoutWidget_3)
        self.showBinary.setObjectName("showBinary")
        self.horizontalLayout.addWidget(self.showBinary)
        self.verticalLayout_5.addLayout(self.horizontalLayout)
        self.horizontalLayoutWidget_2 = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(50, 10, 441, 41))
        self.horizontalLayoutWidget_2.setObjectName("horizontalLayoutWidget_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.startButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_2)
        self.startButton.setObjectName("startButton")
        self.horizontalLayout_2.addWidget(self.startButton)
        self.stopButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_2)
        self.stopButton.setObjectName("stopButton")
        self.horizontalLayout_2.addWidget(self.stopButton)
        self.importButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_2)
        self.importButton.setObjectName("importButton")
        self.horizontalLayout_2.addWidget(self.importButton)
        self.outputButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_2)
        self.outputButton.setObjectName("outputButton")
        self.horizontalLayout_2.addWidget(self.outputButton)
        self.verticalLayoutWidget_4 = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(1540, 150, 195, 771))
        self.verticalLayoutWidget_4.setObjectName("verticalLayoutWidget_4")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_4)
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.widget = QtWidgets.QWidget(Form)
        self.widget.setGeometry(QtCore.QRect(1540, 50, 193, 791))
        self.widget.setObjectName("widget")
        self.gridLayout = QtWidgets.QGridLayout(self.widget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.ipProtocol = QtWidgets.QTextBrowser(self.widget)
        self.ipProtocol.setObjectName("ipProtocol")
        self.gridLayout.addWidget(self.ipProtocol, 6, 1, 1, 1)
        self.label_7 = QtWidgets.QLabel(self.widget)
        self.label_7.setObjectName("label_7")
        self.gridLayout.addWidget(self.label_7, 6, 0, 1, 1)
        self.label_11 = QtWidgets.QLabel(self.widget)
        self.label_11.setObjectName("label_11")
        self.gridLayout.addWidget(self.label_11, 0, 0, 1, 1)
        self.label_9 = QtWidgets.QLabel(self.widget)
        self.label_9.setObjectName("label_9")
        self.gridLayout.addWidget(self.label_9, 9, 0, 1, 1)
        self.httpProtocol = QtWidgets.QTextBrowser(self.widget)
        self.httpProtocol.setObjectName("httpProtocol")
        self.gridLayout.addWidget(self.httpProtocol, 2, 1, 1, 1)
        self.udpProtocol = QtWidgets.QTextBrowser(self.widget)
        self.udpProtocol.setObjectName("udpProtocol")
        self.gridLayout.addWidget(self.udpProtocol, 4, 1, 1, 1)
        self.tcpProtocol = QtWidgets.QTextBrowser(self.widget)
        self.tcpProtocol.setObjectName("tcpProtocol")
        self.gridLayout.addWidget(self.tcpProtocol, 3, 1, 1, 1)
        self.label_8 = QtWidgets.QLabel(self.widget)
        self.label_8.setObjectName("label_8")
        self.gridLayout.addWidget(self.label_8, 4, 0, 1, 1)
        self.arpProtocol = QtWidgets.QTextBrowser(self.widget)
        self.arpProtocol.setObjectName("arpProtocol")
        self.gridLayout.addWidget(self.arpProtocol, 7, 1, 1, 1)
        self.icmpProtocol = QtWidgets.QTextBrowser(self.widget)
        self.icmpProtocol.setObjectName("icmpProtocol")
        self.gridLayout.addWidget(self.icmpProtocol, 5, 1, 1, 1)
        self.protocolSum = QtWidgets.QTextBrowser(self.widget)
        self.protocolSum.setObjectName("protocolSum")
        self.gridLayout.addWidget(self.protocolSum, 9, 1, 1, 1)
        self.label_6 = QtWidgets.QLabel(self.widget)
        self.label_6.setObjectName("label_6")
        self.gridLayout.addWidget(self.label_6, 7, 0, 1, 1)
        self.label_3 = QtWidgets.QLabel(self.widget)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 2, 0, 1, 1)
        self.label_5 = QtWidgets.QLabel(self.widget)
        self.label_5.setObjectName("label_5")
        self.gridLayout.addWidget(self.label_5, 3, 0, 1, 1)
        self.label_4 = QtWidgets.QLabel(self.widget)
        self.label_4.setObjectName("label_4")
        self.gridLayout.addWidget(self.label_4, 5, 0, 1, 1)
        self.label_10 = QtWidgets.QLabel(self.widget)
        self.label_10.setObjectName("label_10")
        self.gridLayout.addWidget(self.label_10, 1, 0, 1, 1)
        self.dnsProtocol = QtWidgets.QTextBrowser(self.widget)
        self.dnsProtocol.setObjectName("dnsProtocol")
        self.gridLayout.addWidget(self.dnsProtocol, 1, 1, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "     选择网卡"))
        self.label_2.setText(_translate("Form", "     输入规则"))
        item = self.protocolTable.horizontalHeaderItem(0)
        item.setText(_translate("Form", "源IP"))
        item = self.protocolTable.horizontalHeaderItem(1)
        item.setText(_translate("Form", "目的IP"))
        item = self.protocolTable.horizontalHeaderItem(2)
        item.setText(_translate("Form", "协议类型"))
        item = self.protocolTable.horizontalHeaderItem(3)
        item.setText(_translate("Form", "长度"))
        self.showLayers.headerItem().setText(0, _translate("Form", "协议分析"))
        __sortingEnabled = self.showLayers.isSortingEnabled()
        self.showLayers.setSortingEnabled(False)
        self.showLayers.topLevelItem(0).setText(0, _translate("Form", "链路层数据"))
        self.showLayers.topLevelItem(0).child(0).setText(0, _translate("Form", "源MAC地址："))
        self.showLayers.topLevelItem(0).child(1).setText(0, _translate("Form", "目的MAC地址："))
        self.showLayers.topLevelItem(1).setText(0, _translate("Form", "IP层数据"))
        self.showLayers.topLevelItem(1).child(0).setText(0, _translate("Form", "版本："))
        self.showLayers.topLevelItem(1).child(1).setText(0, _translate("Form", "源IP："))
        self.showLayers.topLevelItem(1).child(2).setText(0, _translate("Form", "目的IP："))
        self.showLayers.topLevelItem(1).child(3).setText(0, _translate("Form", "上层协议："))
        self.showLayers.topLevelItem(1).child(4).setText(0, _translate("Form", "长度："))
        self.showLayers.topLevelItem(2).setText(0, _translate("Form", "运输层数据"))
        self.showLayers.topLevelItem(2).child(0).setText(0, _translate("Form", "协议类型："))
        self.showLayers.topLevelItem(2).child(1).setText(0, _translate("Form", "源端口号："))
        self.showLayers.topLevelItem(2).child(2).setText(0, _translate("Form", "目的端口号："))
        self.showLayers.topLevelItem(2).child(3).setText(0, _translate("Form", "长度"))
        self.showLayers.topLevelItem(3).setText(0, _translate("Form", "应用层数据"))
        self.showLayers.setSortingEnabled(__sortingEnabled)
        self.startButton.setText(_translate("Form", "开始"))
        self.stopButton.setText(_translate("Form", "停止"))
        self.importButton.setText(_translate("Form", "导入"))
        self.outputButton.setText(_translate("Form", "导出"))
        self.label_7.setText(_translate("Form", "IP"))
        self.label_11.setText(_translate("Form", "流量统计"))
        self.label_9.setText(_translate("Form", "合计"))
        self.label_8.setText(_translate("Form", "UDP"))
        self.label_6.setText(_translate("Form", "arp"))
        self.label_3.setText(_translate("Form", "HTTP"))
        self.label_5.setText(_translate("Form", "TCP"))
        self.label_4.setText(_translate("Form", "ICMP"))
        self.label_10.setText(_translate("Form", "dns"))
