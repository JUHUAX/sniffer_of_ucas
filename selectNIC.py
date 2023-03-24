from winpcapy import WinPcapDevices

def getNIC(op="all"):
    NIC = WinPcapDevices.list_devices()
    if op == "all":
        return NIC
    
    if op == "name":
        return list(NIC.keys())
    
    if op == "description":
        return list(NIC.values())
    
print(getNIC("all"))