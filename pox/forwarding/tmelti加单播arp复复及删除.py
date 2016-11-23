# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.util import dpidToStr
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
#log = core.getLogger()
import thread
import string
import re
import socket
import struct
import time
import copy
from pox.lib.util import str_to_bool

file = open("/home/yaozhen/pox.txt",'w')

log = core.getLogger()

# switch :{switch : port number}
adjacency = {}

######ycj
cha_socinited = {}   # dpid : mark, marks if the channels of the switch have been set to the real value after initialization (1 for yes, 0 for no)
paths_map = {}       # dpid : {dpid : path}, stores the pathes that have existed
######ycj

iptomac = {}  # client ip : mac

# client  ethaddr -> (switch, port)
mac_map = {}

# dpid : switch
switches = {}

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 30
FLOW_HARD_TIMEOUT = 60

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4


_7_bat = '92:75:77:12:04:EA'
_8_bat = '3E:2E:A2:91:9B:38'
_9_bat = '86:25:97:EC:C8:72' 
#mesh_bat0_mac = {7:EthAddr(_7_bat),8:EthAddr(_8_bat),9:EthAddr(_9_bat)}
mesh_bat0_mac = {}
channel = {}  ##dpid : {dpid : linksituation} the larger the value of linksituation is,the worst the linksituation is 
#init_channel = {}
temp_channel = {}
channel_flag = 0
defaultchannel = 100

#########################################################a sw join in controller pox,reinit channel
def initial_channel():
        #print len(channel.keys())
        #print len(switches.keys())
        ##when a sw disconnect to or join in controller pox,the switches.keys() change ,reinit channel ;!!!!the situation a sw disconnect to controller,the len(switches.keys()) cant change ,
        global file
        if len(channel.keys()) != len(switches.keys()):
          print 'len(channel.keys()) != len(switches.keys()):'
          print len(channel.keys())
          print len(switches.keys())
          file.write('len(channel.keys()) != len(switches.keys()):\n')
          file.write(str(len(channel.keys()))+'\n')
          file.write(str(len(switches.keys()))+'\n')
          initchannel()
        else:
          for i in channel.keys():
            if len(channel[i].keys())!=len(switches.keys())-1:##when this situation happens ,reinit channel 
              print 'len(channel[i].keys())!=len(switches.keys())-1:'
              print len(channel[i].keys())
              print len(switches.keys())-1
              file.write('len(channel[i].keys())!=len(switches.keys())-1:\n')
              file.write(str(len(channel[i].keys()))+'\n')
              file.write(str(len(switches.keys())-1)+'\n')
              initchannel()
              break
      
#########################################################a sw  join in controller pox,reinit channel              

#########################################################get channel
def generate_channel():
  ControllerIP = '210.45.76.99'
  #ControllerIP = '10.0.0.200'
  Controller_Listen_Event_Port = 5560

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  s.bind((ControllerIP, Controller_Listen_Event_Port))
  s.listen(30)
  
  temp = len(switches.keys())
  time.sleep(10)
  while 1:  ##when all switch connect , we get channel
    if len(switches.keys()) == temp:
      break
    else:
      temp = len(switches.keys())
    time.sleep(3)
    
  ##initial channel
  initchannel()
  '''
  global channel ,init_channel
  for i in switches.keys():
    dicc = {}
    for j in switches.keys():
      if i != j:
        dicc[j] = 1
    #print dicc
    init_channel[int(i)] = dicc  
  channel = init_channel.copy()
  print 'init_channel'
  print init_channel
  print channel
  '''
  while 1:
    client_sock, client_addr = s.accept()
    thread.start_new_thread(handle,(client_sock, client_addr))
	
def initchannel():
  ##initial channel
  global channel ,defaultchannel
  init_channel = {}
  for i in switches.keys():
    cha_socinited[i] = 0       ######ycj # the channel is initialized to 100, mark the cha_socinited to 0
    dicc = {}
    for j in switches.keys():
      if i != j:
        dicc[j] = defaultchannel
    #print dicc
    init_channel[int(i)] = dicc  
  channel = init_channel.copy()
  print 'init_channel'
  print init_channel
  print channel


def handle(client_sock, client_addr):

  dic = {}    # dic : {ssid name:channel value}
  dicc = {}     # dicc : {dpid:channel value}, dicc = mesh_point(dic)
  c=[]
  d=[]
  e=[]
  global file
	
  while 1:
    msg = client_sock.recv(1024)
    #print msg
    if len(msg)==0:
      break
    c = msg.split('\n')
    for i in c:
      d.append(i)
    #print d
  print 'recv finish'  
  for i in d:
    if i is '':
      continue
    e.append(i)
  dpid = e[0].split('#')[0]         # self ssid name
  batmac = e[0].split('#')[1]         # self batmac
  mesh_bat0_mac[int(dpid)] = EthAddr(batmac)
  print mesh_bat0_mac
  for i in range(1,len(e)): 
    if int(e[i].split('#')[1])<0:
      dic[e[i].split('#')[0]]=-int(e[i].split('#')[1])
    else:
      dic[e[i].split('#')[0]]=int(e[i].split('#')[1])
        
  dicc = {}	
  dicc = mesh_point(dic)
        
  global channel,temp_channel,switches
  
  ''' ######ycj
  for i in dicc.keys():##change channel with channel[int(dpid[0])][i],when a sw not in dicc.keys(),means it not within the scope of dpid[0].then it will remain init value 100
    channel[int(dpid)][i] = dicc[i]
  #channel[int(dpid[0])] = dicc
  ''' ######ycj
  ######ycj
  for i in switches.keys():
    if i in dicc.keys():
      channel[int(dpid)][i] = dicc[i]
    elif i != int(dpid):
      channel[int(dpid)][i] = 100
  ######ycj

  print 'The number of channels: ' + str(len(channel.keys()))
  print 'The number of switches: ' + str(len(switches.keys()))
  file.write('The number of channels: ' + str(len(channel.keys()))+'\n')
  file.write('The number of switches: ' + str(len(switches.keys()))+'\n')
  ##when a sw disconnect to or join in controller pox,the switches.keys() change ,reinit channel ;!!!!the situation a sw disconnect to controller,the len(switches.keys()) cant change ,
  initial_channel()

  ######ycj
  cha_socinited[int(dpid)] = 1;     # marks that the switch has been communicated with the controller after the initialization
                                    # that means the channels of the switch have been set to the real value
  if len(cha_socinited) == sum(cha_socinited.values()):   # if all the channels have been set to the real value 
    cha_reverse = channelreverse(channel)   # dpid : channel[], reverse the meaning of channel
    for i in cha_reverse:
      #if cha_reverse[i].count(100) == len(cha_reverse[i]) and channel[i].values().count(100) == len(channel[i].values()):  # all the channels connected to the switch is 100, means the switch is down
      if cha_reverse[i].count(100) == len(cha_reverse[i]):
        print "*******************************************"
        print dpidToStr(i) + " is going down...deleting paths..."
        print "*******************************************" 
        file.write("*******************************************\n")
        file.write(dpidToStr(i) + " is going down...deleting paths...\n")
        file.write("*******************************************\n")
        temp = {}
        for m in paths_map:
          for n in paths_map[m]:
            if i in paths_map[m][n]:
              if temp.has_key(m):
                temp[m].append(n)
              else:
                temp[m] = [n]
        for m in temp:
          for n in temp[m]:
            path = paths_map[m].pop(temp[m])    # delete the relating existed paths
            if i != path[0]:
              msg = of.ofp_flow_mod(command = OFPFC_DELETE_STRICT)
              msg.match.dl_src = m
              msg.match.dl_dst = n
              switches[path[0]].connection.send(msg)
            print path
        if switches.has_key(i):	
          sw = switches[i]
          sw.disconnect()
          del switches[i]           # delete the switch
        if channel.has_key(i):
          del channel[i]            # delete the channels of the switch
        for j in channel:
          if channel[j].has_key(i):
            del channel[j][i]       # delete the channels connected to the switch
  ######ycj
		
  global adjacency
  adjacency = channeltoadj(channel)
  #print '***************************************************************************'
  #print 'adjacency'+str(adjacency)
  #print '***************************************************************************'
  #print 'switches'+str(switches)
  print '***************************************************************************'
  print 'channel:'+str(channel)
  print '***************************************************************************'
  print 'clients:' + str(iptomac)
  print '***************************************************************************'
  #file.write('***************************************************************************\n')
  #file.write('adjacency'+str(adjacency)+'\n')
  #file.write('***************************************************************************\n')
  #file.write('switches'+str(switches)+'\n')
  file.write('***************************************************************************\n')
  file.write('channel:'+str(channel)+'\n')
  file.write('***************************************************************************\n')
  file.write('clients:'+str(iptomac)+'\n')
  file.write('***************************************************************************\n')

######ycj
def channelreverse(cha):   # reverse the meaning of the global channel
  cha_re = {}             # dpid : channel[], the channel[] means the channel connected to the switch, not the channel connected to the others
  for i in cha:
    cha_re[i] = []
  for i in cha:
    for j in cha[i]:
      cha_re[j].append(cha[i][j])
  return cha_re

def channeltoadj(cha):
  dic = {}
  global defaultchannel
  for i in cha.keys():
    dic[switches[i]] = {}
    for j in cha[i].keys():
      if cha[i][j] != defaultchannel :
        dic[switches[i]][switches[j]] = 6
  return dic
  
        
def mesh_point(dic):  
  dicc = {}
  a = dic.keys()
  str = 'OpenWrt\d_3800'
  c = []
  for i in a:
    if len(re.findall(str,i)) is 0:
      continue
    else:
      c.append(re.findall(str,i)[0])
      for j in switches.keys():
        if j == int(re.findall(str,i)[0][7]):
          dicc[int(re.findall(str,i)[0][7])] = dic[i]
      #print re.findall(str,i)[0]
  return dicc

#########################################################get channel


#########################################################get path
def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports

  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[2]:
      return False
  return True

def generate_graph():
  graph = {}
  global adjacency
  #print adjacency
  #file.write(str(adjacency) + '\n')
  for sw in adjacency:
    graph[sw.dpid] = []
    for sw1 in adjacency[sw]:
      graph[sw.dpid].append(sw1.dpid)  
  #print '########################'
  print '***********************************************'
  print 'graph: ' + str(graph)
  file.write('***********************************************\n')
  file.write('graph: ' + str(graph) + '\n')
  return graph

def find_all_paths(graph, start, end, path=[]):   #start:first switch dpid, end:last switch dpid
        path = path + [start]    #path includes start and end
        if start == end:
            return [path]
        if not graph.has_key(start):
            return []
        paths = []
        for node in graph[start]:
            if node not in path:
                newpaths = find_all_paths(graph, node, end, path)
                for newpath in newpaths:
                    paths.append(newpath)
        return paths

def chose_path(start,end,channel):##according to channel and hop to decide the final path from allpath
  #print start
  #print end
  global file
  #print '**************************************************'
  #print 'channel:'
  #print channel
  #print 'src dpid: '+str(start)
  #print 'dst dpid: '+str(end)
  paths_dic={}
  maxi=0
  whole_maxi={}
  whole_min = 1000
  min_hop = 100
  count = {}
  graph = generate_graph()
  #print graph
  paths = find_all_paths(graph, start, end, path=[])
  ##print 'paths = find_all_paths(graph, start, end, path=[])'
  #print channel
  #print 'paths:'
  #print paths
  #print '**************************************************'
  #file.write('**************************************************\n')
  #file.write('channel:'+'\n')
  #file.write(str(channel)+'\n')
  #file.write('src dpid: '+str(start)+'\n')
  #file.write('dst dpid: '+str(end)+'\n')
  #file.write('paths:'+'\n')
  #file.write(str(paths)+'\n')
  #file.write('**************************************************\n')
  for j in range(0,len(paths)):
    paths_dic[j+1] = paths[j] 
  ##print paths_dic
  for j in paths_dic:##calc every path the worst linksituation
    for i in range(0,len(paths_dic[j])-1):
      if channel[paths_dic[j][i]][paths_dic[j][i+1]]>=maxi:
        maxi = channel[paths_dic[j][i]][paths_dic[j][i+1]]
    
    whole_maxi[j]=maxi
    maxi=0 ##important !!!!when each path maxi finished ,make maxi 0,start the nest path
  ##print whole_maxi
  for i in whole_maxi: ##chose a better one, (linksituation is small)
    if whole_maxi[i]<whole_min:
      whole_min = whole_maxi[i]
  #print whole_min    
  for i in whole_maxi:
    if whole_min == whole_maxi[i]:
      count[i] = whole_min
  #print '*****************************************************'
  #print 'The count of optimal path:'+str(len(count.keys()))
  #print '*****************************************************'
  #file.write('*****************************************************\n')
  #file.write('The count of optimal path:'+str(len(count.keys()))+'\n')
  #file.write('*****************************************************\n')
  if len(count.keys())>1:
    for i in count:
      if len(paths_dic[i])<min_hop:
        min_hop = len(paths_dic[i])
    for i in count:
      if  min_hop ==  len(paths_dic[i]):
          return paths_dic[i]
  else:
    #print paths_dic[count.keys()[0]]
    return paths_dic[count.keys()[0]]

def _get_path (srcmac, dstmac ):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  global file
  global mac_map
  #print mac_map
  #print srcmac
  #print dstmac
  first_port = mac_map[srcmac][1]
  final_port = mac_map[dstmac][1]
  #print first_port

  #print mac_map[srcmac][0]
  src = mac_map[srcmac][0]
  dst = mac_map[dstmac][0]
  path = chose_path(src.dpid,dst.dpid,channel)

  ######ycj
  global paths_map
  path.reverse()
  pathre = copy.deepcopy(path)
  path.reverse()
  #srcdpid = path[0]
  #dstdpid = path[len(path)-1]
  if srcmac in paths_map:
    if dstmac in paths_map[srcmac]:
      if path != paths_map[srcmac][dstmac]:      # the path is different with the path stored in paths_map 
        print "***************************************"
        print "Path alternated!!!!!"
        print paths_map[srcmac][dstmac]
        print " --> "
        print path
        print pathre
        print "***************************************"
        file.write("***************************************\n")
        file.write("Path alternated!!!!!")
        file.write(str(paths_map[srcmac][dstmac]))
        file.write(" --> ")
        file.write(str(path))
        file.write(str(pathre))
        file.write("***************************************\n")
        paths_map[srcmac][dstmac] = path
        paths_map[dstmac][srcmac] = pathre
    else:
      print "**************************************"
      print "New path get!!!!!"
      print path
      print pathre
      print "**************************************"
      file.write("***************************************\n")
      file.write("New path get!!!!!")
      file.write(str(path))
      file.write(str(pathre))
      file.write("***************************************\n")
      paths_map[srcmac][dstmac] = path
      if not paths_map.has_key(dstmac):
        paths_map[dstmac] = {}
      paths_map[dstmac][srcmac] = pathre
  else:	
    print "***************************************"
    print "New path get!!!!!"
    print path
    print pathre
    print "***************************************"
    file.write("***************************************\n")
    file.write("New path get!!!!!")
    file.write(str(path))
    file.write(str(pathre))
    file.write("***************************************\n")
    paths_map[srcmac] = {}
    paths_map[srcmac][dstmac] = path
    if not paths_map.has_key(dstmac):
      paths_map[dstmac] = {}
    paths_map[dstmac][srcmac] = pathre
  ######ycj

  print '_handle_PacketIn() -> install_path() -> _get_path() -> chose_path() -> channel path'
  print '*********************************************************************'
  #print 'channel:'+str(channel)
  #print '*********************************************************************' 
  print 'path:'+str(path)
  file.write('_handle_PacketIn() -> install_path() -> _get_path() -> chose_path() -> channel path')
  file.write('*********************************************************************\n')
  #file.write('channel:'+str(channel))
  #file.write('*********************************************************************\n')
  file.write('path:'+str(path))
  r = []
  #print 'path = chose_path(mac_map[srcmac][0].dpid,mac_map[dstmac][0].dpid,channel)'
  #print path
  mesh_path = {}
  #mesh_path[1] = (srcmac,0,mac_map[srcmac][1])
  if len(path) == 1:
    mesh_path[1] = (src,first_port,final_port)
  else :  
    if len(path) == 2:
      #mesh_path[len(path)+2] = (dstmac,mac_map[dstmac][1],0)
      mesh_path[1] = (src,first_port,adjacency[switches[path[0]]][switches[path[1]]])
      mesh_path[2] = (dst,adjacency[switches[path[len(path)-1]]][switches[path[len(path)-2]]],final_port)
    else:
      mesh_path[1] = (src,first_port,adjacency[switches[path[0]]][switches[path[1]]])
      mesh_path[len(path)] = (dst,adjacency[switches[path[len(path)-1]]][switches[path[len(path)-2]]],final_port)
      for i in range(2,len(path)):
        mesh_path[i] = (switches[path[i-1]], adjacency[switches[path[i-1]]][switches[path[i-2]]] , adjacency[switches[path[i-1]]][switches[path[i]]] )
  #print mesh_path
  r = mesh_path.values()

  #assert _check_path(r), "Illegal path!"

  return r

class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None
    self.macToPort = {}


  def __repr__ (self):  ##make switches() from {8: <pox.forwarding.tmesh_noadj.LearningSwitch object at 0xb570d76c>, 9: <pox.forwarding.tmesh_noadj.LearningSwitch object at 0xb570d2cc>, 7: <pox.forwarding.tmesh_noadj.LearningSwitch object at 0xb570650c>}  to {8: 00-00-00-00-00-08, 9: 00-00-00-00-00-09, 7: 00-00-00-00-00-07}
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, mac , originmac , buf = None):
    #print '_install (self, switch, in_port, out_port, match, mac ,buf = None):'
    msg = of.ofp_flow_mod()
    #msg.match = match

    #msg.match.dl_dst =  mesh_bat0_mac[self.dpid]   ### CANT because the first mesh point doesnt match
    msg.match.in_port = in_port
    msg.match.dl_type = match.dl_type
    msg.match.nw_tos = match.nw_tos
    msg.match.nw_proto = match.nw_proto
    msg.match.nw_src = match.nw_src
    msg.match.nw_dst = match.nw_dst
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.match.dl_src = match.dl_src
    #msg.match.dl_dst = match.dl_dst
    if match.dl_type != 0x0806:
      msg.match.dl_dst = originmac      ####ycj
    #msg.buffer_id = buf
    #msg.match.dl_dst = match.dl_dst      ### CANT because the dl_dst doesnt change
    msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
    if in_port == out_port:
      msg.actions.append(of.ofp_action_output(port = 0xfff8))
    else:
      msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)
    #print '***********************************************************'
    print 'installing ' + str(msg.xid) + ' in ' + str(switch.dpid)
    #file.write('***********************************************************\n')
    file.write('installing ' + str(msg.xid) + ' in ' + str(switch.dpid) +'\n')

  def _install_path (self, p, match, packet_in=None):  
    wp = WaitingPath(p, packet_in)     
    #for sw,in_port,out_port in p:
    if len(p) == 1:
      self._install(p[0][0], p[0][1], p[0][2], match ,match.dl_dst , match.dl_dst)
    else:
      for i in range(0,len(p)):
        #print '_install_path (self, p, match, packet_in=None):'
        #print i
        if i is not (len(p)-1):
          if i == 0:                ####ycj
            self._install(p[i][0], p[i][1], p[i][2], match ,mesh_bat0_mac[int(p[i+1][0].dpid)] , match.dl_dst)
          else:
            self._install(p[i][0], p[i][1], p[i][2], match ,mesh_bat0_mac[int(p[i+1][0].dpid)] , mesh_bat0_mac[int(p[i][0].dpid)])
        else:
          self._install(p[i][0], p[i][1], p[i][2], match ,match.dl_dst , mesh_bat0_mac[int(p[i][0].dpid)])
        msg = of.ofp_barrier_request()
        p[i][0].connection.send(msg)
        wp.add_xid(p[i][0].dpid,msg.xid)
        print '***********************************************************'
        print 'The ' + str(msg.xid) + ' in ' + str(p[i][0].dpid) + ' has been installed!'
        #print 'The barrier request in has been sent to ' + str(p[i][0].dpid) + '!'
        #print '***********************************************************'
        file.write('***********************************************************\n')
        file.write('The ' + str(msg.xid) + ' in ' + str(p[i][0].dpid) + ' has been installed!'+'\n')
        #file.write('The barrier request in has been sent to ' + str(p[i][0].dpid) + '!'+'\n')
        #file.write('***********************************************************\n')

  def install_path (self,src, dst, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    global file
    p = _get_path(src, dst)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)
      file.write("Can't get from %s to %s \n" % (match.dl_src, match.dl_dst))

      import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)
        file.write("Dest unreachable (%s -> %s \n)" %
                  (match.dl_src, match.dl_dst))

        from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')

        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)

      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))
    file.write("Installing path for %s -> %s %04x (%i hops) \n" %
        (match.dl_src, match.dl_dst, match.dl_type, len(p)))

    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    ##############the path order is important,change it
    c=[]
    for i in range(0,len(p)):
      c.append(p[len(p)-1-i])
    self._install_path(c, match.flip())
    ##############the path order is important,change it
    #print match
    #print match.flip()

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    global file
    packet = event.parsed

    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
        file.write("Not flooding -- holddown active\n")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      #print '**************************************************************'
      #print 'THe packetIn is flooding!!!'
      #print '**************************************************************'
      file.write('**************************************************************\n')
      file.write('THe packetIn is flooding!!!\n')
      file.write('**************************************************************\n')
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        print '**************************************************************'
        print 'THe packetIn is drop!!!'
        print '**************************************************************'
        file.write('**************************************************************\n')
        file.write('THe packetIn is drop!!!\n')
        file.write('**************************************************************\n')
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1
    
    match = of.ofp_match.from_packet(packet)
  
    iptomac[match.nw_src] = match.dl_src
    if match.dl_dst != EthAddr("ff:ff:ff:ff:ff:ff"):
      iptomac[match.nw_dst] = match.dl_dst
    
    global mac_map
    for key,value in self.macToPort.iteritems():
      if value != 6:
        mac_map[key]=(self,value)#note the sw which client is connected with
    
    #print '********************************************************************'
    #print 'switch dpid:'+str(self.dpid)
    #print 'nw_src:'+str(match.nw_src)
    #print 'inport:'+str(event.port)
    #print 'dl_dst:'+str(match.dl_dst)
    #file.write('********************************************************************\n')
    #file.write('switch dpid:'+str(self.dpid)+'\n')
    #file.write('nw_src:'+str(match.nw_src)+'\n')
    #file.write('inport:'+str(event.port)+'\n')
    #file.write('dl_dst:'+str(match.dl_dst)+'\n')
    
    if match.dl_type == 2054:   #0x0806
      print '********************************************************************'
      print 'switch dpid:'+str(self.dpid)
      print 'nw_src:'+str(match.nw_src)
      print 'inport:'+str(event.port)
      print 'dl_dst:'+str(match.dl_dst)
      file.write('********************************************************************\n')
      file.write('switch dpid:'+str(self.dpid)+'\n')
      file.write('nw_src:'+str(match.nw_src)+'\n')
      file.write('inport:'+str(event.port)+'\n')
      file.write('dl_dst:'+str(match.dl_dst)+'\n')
      if match.nw_proto == 1:
        print 'arp request'
        file.write('arp request\n')
      elif match.nw_proto == 2:
        print 'arp answer'
        file.write('arp answer\n')
      else:
        print 'arp unknown'
        file.write('arp unknown\n')
    elif match.dl_type == 2048:   #0x0800
      if match.nw_proto == 1:
        print '********************************************************************'
        print 'switch dpid:'+str(self.dpid)
        print 'nw_src:'+str(match.nw_src)
        print 'inport:'+str(event.port)
        print 'dl_dst:'+str(match.dl_dst)
        print 'icmp'
        file.write('********************************************************************\n')
        file.write('switch dpid:'+str(self.dpid)+'\n')
        file.write('nw_src:'+str(match.nw_src)+'\n')
        file.write('inport:'+str(event.port)+'\n')
        file.write('dl_dst:'+str(match.dl_dst)+'\n')
        file.write('icmp\n')
        '''
      elif match.nw_proto == 6:
        print 'tcp'
        file.write('tcp\n')
      elif match.nw_proto == 17:
        print 'udp'
        file.write('udp\n')
      else:
        print 'ip unknown'
        file.write('ip unknown\n')
    elif match.dl_type == 34525:   #0x86DD
      print 'ipv6'
      file.write('ipv6\n')
    else:
      print 'unknown'
      file.write('unknown\n')
      '''
    #print '********************************************************************'
    file.write('********************************************************************\n')
    
    #print self.dpid
    #print match
    #print iptomac
    #print self.macToPort
    #print mac_map

    #loc = (self, event.port) # Place we saw this ethaddr
    #oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if match.dl_type == 2054 and match.nw_proto==1 and match.nw_dst in iptomac.keys():
      import pox.lib.packet as pkt
      if match.dl_type == pkt.ethernet.ARP_TYPE:
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.ARP_TYPE
        arpp = pkt.arp()
        arpp.opcode = arpp.REPLY
        arpp.hwsrc = iptomac[match.nw_dst]
        arpp.hwdst = match.dl_src
        arpp.protosrc = match.nw_dst
        arpp.protodst = match.nw_src
        
        e.payload=arpp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)
        
        print '**********************************************************'
        print 'arp reply to ' + str(match.nw_src)
        print '**********************************************************'
        file.write('**********************************************************\n')
        file.write('arp reply to ' + str(match.nw_src)+'\n')
        file.write('**********************************************************\n')
        return

    if packet.dst.is_multicast:
    #if match.dl_dst == Ethaddr('ff:ff:ff:ff:ff:ff')
      if match.dl_type == 2054 and match.nw_proto==1 and match.nw_dst in iptomac.keys():
        import pox.lib.packet as pkt
        if match.dl_type == pkt.ethernet.ARP_TYPE:
          e = pkt.ethernet()
          e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
          e.dst = match.dl_src
          e.type = e.ARP_TYPE
          arpp = pkt.arp()
          arpp.opcode = arpp.REPLY
          arpp.hwsrc = iptomac[match.nw_dst]
          arpp.hwdst = match.dl_src
          arpp.protosrc = match.nw_dst
          arpp.protodst = match.nw_src
          
          e.payload=arpp
          msg = of.ofp_packet_out()
          msg.actions.append(of.ofp_action_output(port = event.port))
          msg.data = e.pack()
          self.connection.send(msg)

          print '**********************************************************'
          print 'arp reply to' + str(match.nw_src)
          print '**********************************************************'
          file.write('**********************************************************\n')
          file.write('arp reply to' + str(match.nw_src)+'\n')
          file.write('**********************************************************\n')
            
      else:  
        flood() # 3a
    else:
      if packet.dst not in mac_map:
         if packet.dst in mesh_bat0_mac.values(): 
           drop()
         else:
           flood()
      else:
        #dest = mac_map[packet.dst]                         ###ycj
        #match = of.ofp_match.from_packet(packet)           ###ycj
        #print match
        #print 'packet.src'
        #print packet.src
        #print packet.dst
        #print mac_map[packet.src][0].dpid
        print '********************************************'
        print 'install dl_type: ' + str(match.dl_type) + '  install nw_proto: ' + str(match.nw_proto)
        print '********************************************'
        file.write('*******************************************\n')
        file.write('install dl_type: ' + str(match.dl_type) + '  install nw_proto: ' + str(match.nw_proto)+'\n')
        file.write('*******************************************\n')
        self.install_path(packet.src, packet.dst, match, event)
        

  def disconnect (self):
    global file
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      file.write("Disconnect %s \n" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    global file
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    file.write("Connect %s \n" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True

  def _handle_ConnectionDown (self, event):
    self.disconnect()

class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet

    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()

  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self

  @property
  def is_expired (self):
    return time.time() >= self.expires_at

  def notify (self, event):
    global file
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        file.write("Sending delayed packet out %s \n"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    global file
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))
      file.write("%i paths failed to install\n" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    Event.__init__(self)
    self.path = path
    print '***********************************************'
    print 'Path has been installed!' 
    #print '***********************************************'
    file.write('***********************************************\n')
    file.write('Path has been installed!\n')
    #file.write('***********************************************\n')

class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
  ])

  def __init__ (self):
    # Listen to dependencies
    def startup ():
      core.openflow.addListeners(self, priority=0)
      
    core.call_when_ready(startup, ('openflow'))


  def _handle_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)

  def _handle_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      #log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)

def launch ():
  core.registerNew(l2_multi)

  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
  thread.start_new_thread(generate_channel,())   ###get channel thread
