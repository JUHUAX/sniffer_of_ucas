from winpcapy import WinPcapDevices

def getNIC(op="all"):
    NIC = WinPcapDevices.list_devices()
    if op == "all":
        ans = []
        for name, description in NIC.items():
            ans.append(description + ":" + name)
        return ans
    
    if op == "name":
        return list(NIC.keys())
    
    if op == "description":
        return list(NIC.values())
    
#print(getNIC("all"))