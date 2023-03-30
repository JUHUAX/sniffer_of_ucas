from socket import *
import dpkt
    
def doUDP(ucp_packet):

    curPacket = {"protocol":"udp",
        "sport":ucp_packet.sport,
        "dport":ucp_packet.dport,
        "sum":ucp_packet.sum,
        "ulen":ucp_packet.ulen,
        "data":ucp_packet.data
    }
    return curPacket

def doTCP(tcp_packet):

    curPacket = {"protocol":"tcp",
        "sport":tcp_packet.sport,
        "dport":tcp_packet.dport,
        "seq":tcp_packet.seq,
        "ack":tcp_packet.ack,
        "off":tcp_packet.off,
        "flags":tcp_packet.flags,
        "win":tcp_packet.win,
        "sum":tcp_packet.sum,
        "urp":tcp_packet.urp,
        "data":tcp_packet.data
    }
    return curPacket
        # print(curPacket)

def doicmp(icmp_packet):

    curPacket = {"protocol":"icmp",
        "code":icmp_packet.code,
        "sum":icmp_packet.sum,
        "type":icmp_packet.type,
        "data":icmp_packet.data
    }
    return curPacket

def doicmp6(icmp6_packet):

    curPacket = {"protocol":"icmp6",
        "code":icmp6_packet.code,
        "sum":icmp6_packet.sum,
        "type":icmp6_packet.type,
        "data":icmp6_packet.data
    }
    return curPacket


def analysisTrans(data):
    curPacket = {}
    if isinstance(data, dpkt.udp.UDP):
        curPacket = doUDP(data)
        return curPacket
    elif isinstance(data, dpkt.tcp.TCP):
        curPacket = doTCP(data)
        return curPacket
    elif isinstance(data, dpkt.icmp.ICMP):
        curPacket = doicmp(data)
        return curPacket
    elif isinstance(data, dpkt.icmp6.ICMP6):
        curPacket = doicmp6(data)
        return curPacket
    
