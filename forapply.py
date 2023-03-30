from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
from socket import *
import dpkt
import time
import datetime

global ans
ans = {}

def apply_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    apply_packet = eth.data.data.data
    
    

def analysisHttp(data):
    tmp = ""
    print("http!!!")
    if isinstance(data, dpkt.http.Request):
        request = dpkt.http.Request(data)
        request.unpack(tmp)
        packet = {
            "protocol":"http",
            "type":"request",
            "method":request.method,
            "version":request.version,
            "url":request.uri,
            "headers":request.headers,
            "body":request.body
        }
        print(packet["headers"])
    elif isinstance(data, dpkt.http.Response):
        response = dpkt.http.Response(data)
        response.unpack(tmp)
        packet = {
            "protocol":"http",
            "type":"response",
            "version":response.version,
            "status":response.status,
            "reason":response.reason,
            "body":response.body
        }
    
    return packet

def analysisDns(data):
    print("dns!!!")
    if isinstance(data, dpkt.dns.DNS):
        data = dpkt.dns.DNS(data)
        packet = {
            "protocol":"dns",
            "op":data.op,
            "qd":data.qd,
            "an":data.aa
        }
        return packet
    return {
            "protocol":"",
            "op":"",
            "qd":"",
            "an":""
        }
    

def analysisApply(data):
    if isinstance(data, dpkt.http.Request) or isinstance(data, dpkt.http.Response):
        return analysisHttp(data)
    if isinstance(data, dpkt.dns.DNS):
        return analysisDns(data)
    return {}