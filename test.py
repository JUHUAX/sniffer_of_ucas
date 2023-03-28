import winpcapy as wp
 
def get_info():
    device = wp.pcap_lookupdev()   # 调用wp.pcap_lookupdev函数来获取网卡的详细信息 

    print(device)   # 打印获取到的字符串，其中包含所有必要的信息

 
if __name__ == '__main__':   # 运行代码时会走到这里     

    get_info()