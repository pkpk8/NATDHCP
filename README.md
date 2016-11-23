# NATDHCP

<img src="http://img.blog.csdn.net/20161101095806583" width="520" height="320" />

指定连接外网的交换机dpid与端口号，用于实现nat转换与内部ip分配功能# 

./pox.py  misc.nat --outside_port=eth0.1 --dpid=7 openflow.discovery forwarding.l2_pairs samples.pretty_log


