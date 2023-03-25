# sniffer_of_ucas

## todo

- [x] 网卡选择
- [x] 基本的协议解析
  - [ ] packet list
  - [ ] packet details
  - [ ] packet in binary
- [ ] 数据报协议分析分析功能
- [ ] 流量统计
- [ ] 如何识别某种特定类型的应用层报文
- [ ] OS进程追踪
- [ ] 协议过滤
- [ ] 流追踪能力
- [ ] 保存为pcap文件和加载pcap文件

## 时间线

- 2023.3.24：基本上搞明白怎么去抓包解析了，写了ip、ipv6、udp、tcp、icmp、icmp6的解析，明天打算写一下ui
- 2023.3.25：搞定ui，现在遇到一个难题，winpcapy抓包的函数需要传入一个自定义的回调函数，我现在取不了回调函数里面的值
