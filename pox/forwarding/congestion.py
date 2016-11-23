# Copyright 2012 James McCauley
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
A shortest-path forwarding application.

This is a standalone L2 switch that learns ethernet addresses
across the entire network and picks short paths between them.

You shouldn't really write an application this way -- you should
keep more state in the controller (that is, your flow tables),
and/or you should make your topology more static.  However, this
does (mostly) work. :)

Depends on openflow.discovery
Works with openflow.spanning_tree
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str

import time
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
import pox.lib.packet as pkt
import threading
import socket
import fcntl
import struct

import math
from random import randint
from PyQt4 import QtGui, QtCore
import sys


log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}

#{groupid:(sourcemac,sourceip,sourceport)}
#use for judge a packet is in multicast group, in packetin event
globle_sourcegroup = {}


globle_idgroup = {}#{groupid:multicast object}


# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4

guiflag = False
guicon = {}
guiinfo = ""

#switch ports statistics [sw][port] -> data_stat
sw_port_stat = defaultdict(lambda:defaultdict(lambda:None)) 





def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """

  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print

  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)


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


def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None

    path = [src] + path + [dst]

  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))

  assert _check_path(r), "Illegal path!"

  return r


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
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    Event.__init__(self)
    self.path = path


class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)

        #from pox.lib.addresses import EthAddr
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

    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    self._install_path(p, match.flip())


  def _handle_PacketIn (self, event):
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
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
        self.connection.send(msg)

    packet = event.parsed
    #flag is use for judge a packet is a multicast flow
    flag = 0
    #in general if a packet is in a multicast flow the packet is made up by ipv4 and udp
    ip = packet.find('ipv4')
    udp = packet.find('udp')
    if ip is not None and udp is not None:
      
      #print '=============ip+udp====================='
      #globle_sourcegroup is used for store the source information of multicast
      #print globle_sourcegroup
      for ids in globle_sourcegroup.keys():
        #print ids
        if packet.src == EthAddr(globle_sourcegroup[ids][0]) and ip.srcip == IPAddr(globle_sourcegroup[ids][1]) and udp.srcport == globle_sourcegroup[ids][2]:
          print '*************flag = 1*****************'
          flag = 1
          print globle_idgroup
          globle_idgroup[ids].multicast_install()
          break
        else :
          flag = 0
      
    if flag == 1:
      pass
    elif flag == 0:
      
      loc = (self, event.port) # Place we saw this ethaddr
      oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

      if packet.effective_ethertype == packet.LLDP_TYPE:
        drop()
        return

      if oldloc is None:
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif oldloc != loc:
        # ethaddr seen at different place!
        if loc[1] not in adjacency[loc[0]].values():
          # New place is another "plain" port (probably)
          log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                    dpid_to_str(oldloc[0].connection.dpid), oldloc[1],
                    dpid_to_str(   loc[0].connection.dpid),    loc[1])
          if packet.src.is_multicast == False:
            mac_map[packet.src] = loc # Learn position for ethaddr
            log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
        elif packet.dst.is_multicast == False:
          # New place is a switch-to-switch port!
          #TODO: This should be a flood.  It'd be nice if we knew.  We could
          #      check if the port is in the spanning tree if it's available.
          #      Or maybe we should flood more carefully?
          log.warning("Packet from %s arrived at %s.%i without flow",
                      packet.src, dpid_to_str(self.dpid), event.port)
          #drop()
          #return


      if packet.dst.is_multicast:
        log.debug("Flood multicast from %s", packet.src)
        flood()
      else:
        if packet.dst not in mac_map:
          log.debug("%s unknown -- flooding" % (packet.dst,))
          flood()
        else:
          dest = mac_map[packet.dst]
          match = of.ofp_match.from_packet(packet)
          self.install_path(dest[0], dest[1], match, event)

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
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
'''handle-port_stats
def _handle_port_stats(event):
  global guiinfo
  global guiflag
  print "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
  for stat in event.stats:
    #print event.stats
    print "switch" + dpid_to_str(event.dpid) + "port_no:" + str(stat.port_no) + '\n'
    print "rx_bytes:" + str(stat.rx_bytes) + '\n'
    info = ""
    info += "port_no:" + str(stat.port_no) + '\n'
    #info += "rx_packets:" + str(stat.rx_packets) + '\n'
    #info += "tx_packets:" + str(stat.tx_packets) + '\n'
    info += "rx_bytes:" + str(stat.rx_bytes) + '\n'
    info += "tx_bytes:" + str(stat.tx_bytes) + '\n'
    #info += "rx_dropped:" + str(stat.rx_dropped) + '\n'
    #info += "tx_dropped:" + str(stat.tx_dropped) + '\n'
    guiinfo = guiinfo + info
  guiflag = True
'''
# switch ports statistics [sw][port] -> data_stat
# sw_port_stat = defaultdict(lambda:defaultdict(lambda:None)) 
def _handle_port_stats(event):
  #global guiinfo
  #global guiflag
  print "************************************************************\n"
  for stat in event.stats:
   # print "switch" + dpid_to_str(event.dpid) + "port_no:" + str(stat.port_no) + '\n'
   # print "rx_bytes:" + str(stat.rx_bytes) + '\n'
    data_bytes = float(str(stat.rx_bytes)) + float(str(stat.tx_bytes))
    if sw_port_stat[event.dpid][str(stat.port_no)] is None:
      print 'sw_port_stat[event.dpid][str(stat.port_no)] is None\n'
      sw_port_stat[event.dpid][str(stat.port_no)] = data_bytes
    else:
      pre_data_bytes = sw_port_stat[event.dpid][str(stat.port_no)]
      bandwidth_used = (data_bytes - pre_data_bytes)/(5.0*1024)
      sw_port_stat[event.dpid][str(stat.port_no)] = data_bytes
      if bandwidth_used < 1024:
        print 'Switch: ' + dpid_to_str(event.dpid) + ' ' + "port_no: " + str(stat.port_no) + ' ' + 'bandwidth_used:' + str(bandwidth_used) + 'kbps' + '\n'
      else:
        bandwidth_used_M = bandwidth_used/1024.0
        if bandwidth_used_M > 1 and bandwidth < 2:
          core.l2_multi.raiseEvent(Congestion_level1, event.dpid, stat.port_no, )# raise event
        if bandwidth_used_M > 2 and bandwidth < 3:
          core.l2_multi.raiseEvent(Congestion_level2, event.dpid, stat.port_no, )# raise event
        if bandwidth_used_M > 3 :
          print 'CONGESTION LEVEL 3\n'
        print 'Switch: ' + dpid_to_str(event.dpid) + ' ' + "port_no: " + str(stat.port_no) + ' ' + 'bandwidth_used:' + str(bandwidth_used_M) + 'Mbps' + '\n'
  guiflag = True

#the mulde below is used for define three possible event when a multicast run which may be happened
class MulticastInstall(Event):
  def __init__(self,groupid,source,host,port):
    Event.__init__(self)
    self.groupid = groupid
    self.source = source
    self.host = host
    self.port = port

class MulticastInsert(Event):
  def __init__(self,groupid,source,host,port):
    Event.__init__(self)
    self.groupid = groupid
    self.source = source
    self.host = host
    self.port = port

class MulticastDelete(Event):
  def __init__(self,groupid,source,host,port):
    Event.__init__(self)
    self.groupid = groupid
    self.source = source
    self.host = host
    self.port = port
#################Congestion############################

class Congestion_level1(Event):
  def __init__(self,dpid,port_no):
    Event.__init__(self)
    self.dpid = dpid
    self.port_no = port_no

class Congestion_level2(Event):
  def __init__(self,dpid,port_no):
    Event.__init__(self)
    self.dpid = dpid
    self.port_no = port_no

#################Congestion############################

class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
    MulticastInstall,
    MulticastInsert,
    MulticastDelete,
    Congestion_level1,
    Congestion_level2,
  ])

  def __init__ (self):
    
    # Listen to dependencies
    def startup ():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)
    core.call_when_ready(startup, ('openflow','openflow_discovery'))

  def _handle_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])

    l = event.link
    sw1 = switches[l.dpid1]
    sw2 = switches[l.dpid2]

    # Invalidate all flows and path info.
    # For link adds, this makes sure that if a new link leads to an
    # improved path, we use it.
    # For link removals, this makes sure that we don't use a
    # path that may have been broken.
    #NOTE: This could be radically improved! (e.g., not *ALL* paths break)
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()

    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break
    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2

      # If we have learned a MAC on this port which we now know to
      # be connected to a switch, unlearn it.
      bad_macs = set()
      for mac,(sw,port) in mac_map.iteritems():
        #print sw,sw1,port,l.port1
        if sw is sw1 and port == l.port1:
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
        if sw is sw2 and port == l.port2:
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
      for mac in bad_macs:
        del mac_map[mac]

  def _handle_ConnectionUp (self, event):
    global guicon
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)
    
    guicon[dpid_to_str(event.dpid)] = event.connection

  def _handle_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)


#multicast class use for define a multicast flow
#canshu: src = (mac,ip), hst = {mac:ip}, src_port = int
#interface: multicast_install(...), multicast_insert(...), multicast_delete(...)
class multicast(object):
  def __init__(self, src = None, hst = {}, src_port = 0):
    if src is None:
	  print 'input error!init fail!'
    else:
      self.source = src#(sourcemac,sourceip)
      self.multicast_host = hst#{hostmac:hostip}
      self.source_port = src_port
      self.inswitch = mac_map[src[0]][0]
      self.inport = mac_map[src[0]][1]
      self.router_table = {}#{switch object:[(inport,outport)]}
      print 'mulitcast__init'
      
      #gui mumber varities
      self.guisrcmac = self.source[0]
      self.guisrcmacstr = self.guisrcmac.toStr()

      self.guidstmac = []
      self.guidstmacstr = []

      self.guifirstswitch = mac_map[self.guisrcmac][0]
      self.guifirstswitchdpid = dpid_to_str(self.guifirstswitch.dpid)
      
      
      self.guizuboswitch = []
      self.guizuboswitchdpid = []

  def multicast_install(self):
    print 'multicast_install'
    p = []
    srchst = self.source[0]
    sw1 = mac_map[srchst][0]
    firstport = mac_map[srchst][1]
    host_mac = self.multicast_host.keys()
    for hst in host_mac:
      sw2 = mac_map[hst][0]
      finalport = mac_map[hst][1]
      path = _get_path(sw1, sw2, firstport, finalport)
      for s, inp, outp in path:
        p.append((s, inp, outp))
    pp = set(p)
    p = [i for i in pp]
    #print p
    for s, inp, outp in p:
      rs = self.router_table.keys()
      if s not in rs:
        self.router_table[s] = [(inp, outp)]
      else:
        if (inp, outp) not in self.router_table[s]:
          self.router_table[s].append((inp, outp))
        else:
          pass
    rs = self.router_table.keys()
    hs = self.multicast_host.keys()
    print 'routertable'
    print self.router_table
    for s in rs:
      for inp, outp in self.router_table[s]:
        msg = of.ofp_flow_mod()
        #print 'inp'
        #print inp
        #print 'outp'
        #print outp
	msg.match.in_port = inp
        msg.match.dl_type = 0x800
        msg.match.nw_tos= 0
        msg.match.nw_proto=17
	msg.match.nw_src = IPAddr(self.source[1])
	msg.match.tp_src = self.source_port
        msg.command = of.OFPFC_DELETE
        s.connection.send(msg)
        msg = of.ofp_flow_mod()
        msg.idle_timeout = FLOW_IDLE_TIMEOUT
        #msg.hard_timeout = FLOW_HARD_TIMEOUT
	msg.match.in_port = inp
        msg.match.dl_type = 0x800
        msg.match.nw_tos= 0
        msg.match.nw_proto=17
	msg.match.nw_src = IPAddr(self.source[1])
        #print 'msg.match.nw_src'
        #print msg.match.nw_src
	msg.match.tp_src = self.source_port
        #print 'msg.match.tp_src'
        #print msg.match.tp_src
        for h in hs:
	  if s is mac_map[h][0] and s is not mac_map[self.source[0]][0]:
	    msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.multicast_host[h])))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h)))
            print 'changeip'
            break
          else: 
	    pass
        msg.actions.append(of.ofp_action_output(port = outp))
        s.connection.send(msg)

        #print 'switch'
        #print s
        #print msg.match.in_port
        #print msg.match.nw_src
        #print msg.match.tp_src
  
  def multicast_insert(self, hstmac, hstip):
    if hstmac in self.multicast_host.keys():
      print 'the host you want to insert is already in multicast hosts!'
      return
    else:
      self.multicast_host[hstmac] = hstip
      sw1 = mac_map[self.source[0]][0]
      firstport = mac_map[self.source[0]][1]
      sw2 = mac_map[hstmac][0]
      finalport = mac_map[hstmac][1]
      path = _get_path(sw1, sw2, firstport, finalport)
      hs = self.multicast_host.keys()
      #print 'path****************'
      #print path
      #print 'routertable***************'
      #print self.router_table
      for s, inp, outp in path:
        rs = self.router_table.keys()
	if s not in rs:
	  self.router_table[s] = [(inp, outp)]
	  msg = of.ofp_flow_mod()
	  msg.idle_timeout = FLOW_IDLE_TIMEOUT
          #msg.hard_timeout = FLOW_HARD_TIMEOUT
	  msg.match.in_port = inp
          msg.match.dl_type = 0x800
          msg.match.nw_tos= 0
          msg.match.nw_proto=17
	  msg.match.nw_src = IPAddr(self.source[1])
	  msg.match.tp_src = self.source_port
	  
	  for h in hs:
	    if s is mac_map[h][0] and s is not mac_map[self.source[0]][0]:
	      msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.multicast_host[h])))
              msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h)))
              break
            else: 
	      pass
              """^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
              sw1dpid = dpid_to_str(s.dpid)
              for sw2 in switches.values():
                if adjacency[s][sw2] == outp:
                  sw2dpid = dpid_to_str(sw2.dpid)
                  if pox.topoWidget.topologyView.links[(sw1dpid, sw2dpid)].drawArrow:
                    layer = pox.topoWidget.topologyView.links[(sw1dpid, sw2dpid)].layer + 1
                    pox.topoWidget.topologyView.links[(sw1dpid, sw2dpid)].setshowlayer(True, layer)
                  else:
                    pox.topoWidget.topologyView.links[(sw1dpid, sw2dpid)].setshowarrow(True)
                    pox.topoWidget.topologyView.links[(sw1dpid, sw2dpid)].setshowlayer(True, 1)
              #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"""
          msg.actions.append(of.ofp_action_output(port = outp))
	  s.connection.send(msg)
          
	else:
	  if (inp, outp) not in self.router_table[s]:
	    self.router_table[s].append((inp, outp))
            msg = of.ofp_flow_mod()
	    msg.idle_timeout = FLOW_IDLE_TIMEOUT
            #msg.hard_timeout = FLOW_HARD_TIMEOUT
	    msg.match.in_port = inp
            msg.match.dl_type = 0x800
            msg.match.nw_tos= 0
            msg.match.nw_proto=17
	    msg.match.nw_src = IPAddr(self.source[1])
	    msg.match.tp_src = self.source_port
            for inpp, outpp in self.router_table[s]:
              if inpp == inp:
                for h in hs:
                  if s is mac_map[h][0] and outpp is mac_map[h][1] and s is not mac_map[self.source[0]][0]:
                    msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.multicast_host[h])))
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h)))
                  else:
                    pass
                msg.actions.append(of.ofp_action_output(port = outpp))
              else:
                pass
            
            
	    s.connection.send(msg)
          else:
            pass
      print 'routertable***************'
      print self.router_table
        
			
  def multicast_delete(self , hstmac):
    if hstmac not in self.multicast_host.keys():
      print "the host you want to delete is not in multicast hosts!"
      return
    else:
      p1 = []
      srchst = self.source[0]
      sw1 = mac_map[srchst][0]
      firstport = mac_map[srchst][1]
      for hst in self.multicast_host.keys():
        sw2 = mac_map[hst][0]
	finalport = mac_map[hst][1]
	path = _get_path(sw1, sw2, firstport, finalport)
	for s, inp, outp in path:
	  p1.append((s, inp, outp))
      pp1 = set(p1)
	  
      p2 = []
      del self.multicast_host[hstmac]
      srchst = self.source[0]
      sw1 = mac_map[srchst][0]
      firstport = mac_map[srchst][1]
      for hst in self.multicast_host.keys():
        sw2 = mac_map[hst][0]
	finalport = mac_map[hst][1]
	path = _get_path(sw1, sw2, firstport, finalport)
	for s, inp, outp in path:
	  p2.append((s, inp, outp))
      pp2 = set(p2)
	  
      ppdelet = pp1 - pp2
      p_delet = [i for i in ppdelet]
      
      hs = self.multicast_host.keys()
      for s, inp, outp in p_delet:
        self.router_table[s].remove((inp,outp))
	
	if self.router_table[s] == []:
          msg = of.ofp_flow_mod()
          msg.match.in_port = inp
          msg.match.dl_type = 0x800
          msg.match.nw_tos= 0
          msg.match.nw_proto=17
	  msg.match.nw_src = IPAddr(self.source[1])
	  msg.match.tp_src = self.source_port
	  msg.command = of.OFPFC_DELETE
	  s.connection.send(msg)
	  del self.router_table[s]
        else:
          msg = of.ofp_flow_mod()
	  msg.idle_timeout = FLOW_IDLE_TIMEOUT
          #msg.hard_timeout = FLOW_HARD_TIMEOUT
	  msg.match.in_port = inp
          msg.match.dl_type = 0x800
          msg.match.nw_tos= 0
          msg.match.nw_proto= 17
	  msg.match.nw_src = IPAddr(self.source[1])
	  msg.match.tp_src = self.source_port
          for inpp, outpp in self.router_table[s]:
            if inpp == inp:
              for h in hs:
                if s is mac_map[h][0] and outpp is mac_map[h][1] and s is not mac_map[self.source[0]][0]:
                  msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.multicast_host[h])))
                  msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h)))
                else:
                  pass
              msg.actions.append(of.ofp_action_output(port = outpp))
            else:
              pass
	  s.connection.send(msg)
        print 'routertable multicastdelete'
        print self.router_table

class handlemulticast(object):
  def __init__(self):
    
    core.l2_multi.addListeners(self)

  def _handle_MulticastInstall(self,event):
    print 'handle multicastinstall'
    if event.groupid in globle_idgroup.keys():
      return
    else:
      src = (EthAddr(event.source[0]),IPAddr(event.source[1]))
      hst = {}
      hst[EthAddr(event.host[0])] = IPAddr(event.host[1])
      src_port = event.port
      print hst
      globle_idgroup[event.groupid] = multicast(src,hst,src_port)
      globle_idgroup[event.groupid].multicast_install()
	  
  def _handle_MulticastInsert(self,event):
    print 'handle multicastinsert'
    if event.groupid not in globle_idgroup.keys():
      return
    else:
      hostmac = EthAddr(event.host[0])
      hostip = IPAddr(event.host[1])
      globle_idgroup[event.groupid].multicast_insert(hostmac,hostip)
	  
  def _handle_MulticastDelete(self,event):
    print 'handle multicastdelete'
    if event.groupid not in globle_idgroup.keys():
      return 
    else:
      hostmac = EthAddr(event.host[0])
      globle_idgroup[event.groupid].multicast_delete(hostmac)
      if globle_idgroup[event.groupid].router_table == {}:
        del globle_idgroup[event.groupid]
        del globle_sourcegroup[event.groupid]
#############confestion handler##################
  def _handle_Congestion_level1(self, event):
    print 'handle congestion level 1\n'
    print 'event:' + str(event.dpid) + " " + str(event.port_no)

  def _handle_Congstion_level2(self, event):
    print 'handle congestion level 2\n'
    print 'event:' + str(event.dpid) + " " + str(event.port_no)

import thread
def run():
  import string
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  port = 8001
  s.bind(('10.0.0.200',port))
  s.listen(5)
  
  hostname = socket.gethostname()
  hostip = socket.gethostbyname(hostname)
  print hostname
  print hostip
  while True:
    connection , address = s.accept()
    info = connection.recv(1024)
    print info
    information = info.split('#')
    if information[0] == 'b':
      groupid = information[1]
      host = (information[2], information[3])
      source = (information[4], information[5])
      port = string.atoi(information[6])
      globle_sourcegroup[groupid] = (source[0], source[1], port)
      core.l2_multi.raiseEvent(MulticastInstall,groupid,source,host,port)
    if information[0] == 'i':
      groupid = information[1]
      host = (information[2], information[3])
      source = (information[4], information[5])
      port = string.atoi(information[6])
      core.l2_multi.raiseEvent(MulticastInsert,groupid,source,host,port,)
    if information[0] == 'd':
      groupid = information[1]
      host = (information[2], information[3])
      source = (information[4], information[5])
      port = string.atoi(information[6])
      core.l2_multi.raiseEvent(MulticastDelete,groupid,source,host,port,)
    connection.close()
    """
    if len(information) == 7 :
      connection.send('recieve right information')
      groupid = string.atoi(information[0])
      host = (information[1],information[2])
      source = (information[4],information[5])
        
      port = string.atoi(information[6])
      if information[3] == 'b':
        print 'build:'
        globle_sourcegroup[groupid] = (source[0],source[1],port)
        print 'globle_sourcegroup'
        print globle_sourcegroup
        core.l2_multi.raiseEvent(MulticastInstall,groupid,source,host,port)
      if information[3] == 'i':
        core.l2_multi.raiseEvent(MulticastInsert,groupid,source,host,port,)

      if information[3] == 'd':
        core.l2_multi.raiseEvent(MulticastDelete,groupid,source,host,port,)
      

      connection.close()
    """


class Node(QtGui.QGraphicsItem):
    
    def __init__(self, _type, _id, _layer = 1):
        QtGui.QGraphicsItem.__init__(self)
        
        self.id = _id
        self.type = _type
        self.linkList = []
        self.neighbors = {} #"str(port) : str(neighbor.ID)"

        self.newPos = QtCore.QPointF()
        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)
        self.setFlag(QtGui.QGraphicsItem.ItemSendsGeometryChanges)
        self.setZValue(1)
        self.setAcceptHoverEvents(True)

        #Node attributes
        self.isUp = True
        self.showID = True
        self.showNode = True
        self.isSilent = False
        self.ismulti = False

    def boundingRect(self):
        adjust = 2.0
        if self.type == "host":
            return QtCore.QRectF(-35-adjust, -20-adjust, 70+adjust, 30+adjust)
        else:
            return QtCore.QRectF(-40-adjust, -20-adjust, 80+adjust, 30+adjust)

    def paint(self, painter, option, widget):
        if self.showNode:
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(QtGui.QColor(QtCore.Qt.darkGray).light(25))
            """
            if self.type == "host":
                painter.drawRect(-10, -10, 10, 10)
            else:
                painter.drawEllipse(-10, -10, 20, 20)
            """
            #gradient = QtGui.QRadialGradient(-3, -3, 10)
            
            if self.ismulti:
                color = QtGui.QColor(QtCore.Qt.red)
            else:
                if self.type == "host":
                    color = QtGui.QColor(QtCore.Qt.blue)
                else:
                    color = QtGui.QColor(QtCore.Qt.green)
            if option.state & QtGui.QStyle.State_Sunken:
                #gradient.setCenter(3, 3)
                #gradient.setFocalPoint(3, 3)
                if self.isUp:
                    painter.setBrush(QtGui.QBrush(color.light(100)))
                    #gradient.setColorAt(1, color.light(100))
                    #gradient.setColorAt(0, color.light(30))
                else:
                    painter.setBrush(QtGui.QBrush(color.light(80)))
                    #gradient.setColorAt(1, QtGui.QColor(QtCore.Qt.gray).light(80))
                    #gradient.setColorAt(0, QtGui.QColor(QtCore.Qt.gray).light(20))
            else:
                if self.isUp:
                    painter.setBrush(QtGui.QBrush(color.light(60)))
                    #gradient.setColorAt(0, color.light(85))
                    #gradient.setColorAt(1, color.light(25))
                else:
                    painter.setBrush(QtGui.QBrush(color.light(60)))
                    #gradient.setColorAt(0, QtGui.QColor(QtCore.Qt.gray).light(60))
                    #gradient.setColorAt(1, QtGui.QColor(QtCore.Qt.gray).light(10))

            #painter.setBrush(QtGui.QBrush(gradient))
            #painter.setPen(QtGui.QPen(QtCore.Qt.black, 0))
            
            if self.type == "host":
                painter.drawRect(-7, -7, 14, 14)
            else:
                painter.drawEllipse(-10, -10, 20, 20)
            
        if self.showID:
            # Text.
            textRect = self.boundingRect()
            message = str(self.id)
            """
            if self.type == 'switch':
                import string
                ms = string.atoi(message)
                message = hex(ms)
            """
            font = painter.font()
            font.setBold(True)
            
            font.setPointSizeF(6)
            painter.setFont(font)
            painter.setPen(QtCore.Qt.gray)
            painter.drawText(textRect.translated(0.5, 0.5), message)
            painter.setPen(QtGui.QColor(QtCore.Qt.black).light(130))
            painter.drawText(textRect.translated(0, 0), message)

    def mousePressEvent(self, event):
        self.update()
        QtGui.QGraphicsItem.mousePressEvent(self, event)


class Link(QtGui.QGraphicsItem):
    
    def __init__(self, sourceNode, destNode, sport, dport):
        QtGui.QGraphicsItem.__init__(self)
        self.arrowSize = 5.0
        self.source = sourceNode
        self.dest = destNode
        self.sport = sport
        self.dport = dport
        self.sourcePoint = QtCore.QPointF()
        self.destPoint = QtCore.QPointF()
        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)
        self.setAcceptedMouseButtons(QtCore.Qt.RightButton)
        self.setAcceptHoverEvents(False)
        self.isexist = True
        

        # Link attributes
        self.isUp = True        # up/down state  
        self.showLink = True    # Draw link
        self.showID = False     # Draw link ID   
        self.showPorts = True   # Draw connecting ports  
        
        self.drawArrow = False
        self.layer = 0
        self.showlayer = False
        self.adjust()
    def adjust(self):
        if not self.source or not self.dest:
            return

        line = QtCore.QLineF(self.mapFromItem(self.source, 0, 0),\
                                self.mapFromItem(self.dest, 0, 0))
        length = line.length()
        
        if length == 0.0:
            return
        
        linkOffset = QtCore.QPointF((line.dx() * 10) / length, (line.dy() * 10) / length)

        self.prepareGeometryChange()
        self.sourcePoint = line.p1() + linkOffset
        self.destPoint = line.p2() - linkOffset
        """
             
        """

    def boundingRect(self):
        if not self.source or not self.dest:
            return QtCore.QRectF()
        '''
        return QtCore.QRectF(self.sourcePoint,
                             QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                                           self.destPoint.y() - self.sourcePoint.y())).normalized()
        
        '''
        penWidth = 1
        extra = (penWidth + self.arrowSize * (1 + self.layer)) / 2.0

        return QtCore.QRectF(self.sourcePoint,
                             QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                                           self.destPoint.y() - self.sourcePoint.y())).normalized().adjusted(-extra, -extra, extra, extra)

    def paint(self, painter, option, widget):
        if not self.source or not self.dest:
            
            return

        # Draw the line itself.
        if self.showLink:
            
            line = QtCore.QLineF(self.sourcePoint, self.destPoint)
            if line.length() == 0.0:
                return
            
            # Select pen for line (color for util, pattern for state)
            if self.isUp:
                color = QtCore.Qt.gray
                pattern =  QtCore.Qt.SolidLine
                if option.state & QtGui.QStyle.State_Sunken:
                    color = QtGui.QColor(color).light(256)
                else:
                    color = QtGui.QColor(color).light(90)
            else:
                color = QtCore.Qt.darkGray
                pattern = QtCore.Qt.DashLine
            
            if self.showlayer:
                painter.setPen(QtGui.QPen(color, 2 * self.layer, 
                    pattern, QtCore.Qt.RoundCap, QtCore.Qt.RoundJoin))
                painter.drawLine(line)
                offs = 0.2
                offset = QtCore.QPointF(offs,offs)
                sPortPoint = self.sourcePoint + offset 
                dPortPoint = self.destPoint + offset
                textRect = self.boundingRect()
                font = painter.font()
                font.setBold(True)
                font.setPointSize(6)
                painter.setFont(font)
                xx = self.sourcePoint.x()/2+self.destPoint.x()/2
                yy = self.sourcePoint.y()/2+self.destPoint.y()/2
                painter.setPen(QtCore.Qt.green)
                painter.drawText(xx, yy, "layer = " + str(self.layer)) 
            else:
                painter.setPen(QtGui.QPen(color, 1, 
                    pattern, QtCore.Qt.RoundCap, QtCore.Qt.RoundJoin))
                painter.drawLine(line)
        
            # Draw the arrows if there's enough room.
            angle = math.acos(line.dx() / line.length())
            if line.dy() >= 0:
                angle = 2*math.pi - angle

            destArrowP1 = self.destPoint + \
                QtCore.QPointF(math.sin(angle-math.pi/3)*self.arrowSize * (1 + self.layer),
                math.cos(angle-math.pi/3)*self.arrowSize* (1 + self.layer))
            destArrowP2 = self.destPoint + \
                QtCore.QPointF(math.sin(angle-math.pi+math.pi/3)*self.arrowSize* (1 + self.layer),
                math.cos(angle-math.pi+math.pi/3)*self.arrowSize* (1 + self.layer))
            
            if self.drawArrow:
                painter.setBrush(QtCore.Qt.darkGray)
                painter.setPen(QtCore.Qt.gray)
                painter.drawPolygon(QtGui.QPolygonF([line.p2(), \
                    destArrowP1, destArrowP2]))
        
        
        # Draw port numbers
        if self.showPorts:
            offs = 0.2
            offset = QtCore.QPointF(offs,offs)
            sPortPoint = self.sourcePoint + offset 
            dPortPoint = self.destPoint + offset
            textRect = self.boundingRect()
            font = painter.font()
            font.setBold(True)
            font.setPointSize(6)
            painter.setFont(font)
            sx = self.sourcePoint.x()+self.destPoint.x()/12
            sy = self.sourcePoint.y()+self.destPoint.y()/12
            dx = self.sourcePoint.x()/12+self.destPoint.x()
            dy = self.sourcePoint.y()/12+self.destPoint.y()
            

            painter.setPen(QtCore.Qt.green)
            if self.sport is not None:
                painter.drawText(sx, sy, str(self.sport))
            if self.dport is not None:
                painter.drawText(dx, dy, str(self.dport))



    def setshowarrow(self, tof):
        self.drawArrow = tof
        self.update()
          

    def setshowlayer(self, tof, lay = 0):
        self.showlayer = tof
        self.layer = lay
        self.update()


class MainWindow(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)

        self.setWindowTitle('POX Graphical User Interface')
        self.resize(1200, 720)
        #self.statusBar().showMessage('Ready')
        self.center()

        self.infoWidget = InfoWidget(self)
        self.topoWidget = TopoWidget(self)
        
        self.leftvbox = QtGui.QVBoxLayout()
        self.leftvbox.addWidget(self.infoWidget)
        self.left = QtGui.QWidget()
        self.left.setLayout(self.leftvbox)
        self.left.resize(350,720)

        self.rightvbox = QtGui.QVBoxLayout()
        self.rightvbox.addWidget(self.topoWidget)
        self.right = QtGui.QWidget()
        self.right.setLayout(self.rightvbox)
        
        
        self.hSplitter = QtGui.QSplitter(QtCore.Qt.Horizontal)
        self.hSplitter.addWidget(self.left)
        self.hSplitter.addWidget(self.right)

        self.setCentralWidget(self.hSplitter)
        
        self.right.show()
        self.left.show()
        
    def center(self):
        screen = QtGui.QDesktopWidget().screenGeometry()
        size =  self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)



class TopoWidget(QtGui.QWidget):
    def __init__(self, parent = None):
        QtGui.QWidget.__init__(self, parent)
        self.parent = parent
        
        self.topologyView = TopologyView(self)
        self.topolabel = QtGui.QLabel("LAN topology")
        self.topoupdate = QtGui.QPushButton("Update")
        #self.changeViewWidget = ChangeViewWidget(self)
        self.views = {}
        
        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(self.topolabel, 0, QtCore.Qt.AlignHCenter)
        vbox.addWidget(self.topologyView)
        vbox.addWidget(self.topoupdate, 0, QtCore.Qt.AlignHCenter)
        self.setLayout(vbox)
        #self.resize(300, 150)
        
        self.selectedNode = None
        
        self.qtime = QtCore.QTimer()
        QtCore.QObject.connect(self.qtime, QtCore.SIGNAL("timeout()"), self.outtime)
        self.qtime.start(1000)
        
        self.connect(self.topoupdate, QtCore.SIGNAL('clicked()'), self.buttonclicked)

    def buttonclicked(self):
        #self.topologyView.topoScene.clear()
        
        self.topologyView.getnodes()
        self.topologyView.getlinks()
        #print self.topologyView.nodes
        self.topologyView.updateAll()

    def outtime(self):
        self.topologyView.getnodes()
        self.topologyView.getlinks()
        self.topologyView.updateAll()



class TopologyView(QtGui.QGraphicsView):
    #updateAllSignal = QtCore.pyqtSignal()
    
    def __init__(self, parent = None):
        QtGui.QGraphicsView.__init__(self, parent)
        self.parent = parent
        self.setStyleSheet("background: white")
        
        self.nodes = {}
        self.links = {}

        self.topoScene = QtGui.QGraphicsScene(self)
        self.topoScene.setItemIndexMethod(QtGui.QGraphicsScene.NoIndex)
        self.topoScene.setSceneRect(-500, -400, 1000, 800)
        self.setScene(self.topoScene)
        self.setRenderHint(QtGui.QPainter.Antialiasing)
        self.setTransformationAnchor(QtGui.QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QtGui.QGraphicsView.AnchorViewCenter)

        self.scale(0.9,0.9)
        self.setMinimumSize(400, 240)

        self.setDragMode(self.ScrollHandDrag)
        self.setCursor(QtCore.Qt.ArrowCursor)
        #self.updateAllSignal.connect(self.updateAll)
        
    def wheelEvent(self, event):
        """
        Zoom
        """
        self.scaleView(math.pow(2.0, event.delta() / 300.0))
        
    def scaleView(self, scaleFactor):
        factor = self.matrix().scale(scaleFactor, scaleFactor).mapRect(QtCore.QRectF(0, 0, 1, 1)).width()

        if factor < 0.07 or factor > 100:
            return

        self.scale(scaleFactor, scaleFactor)
   
    def mouseMoveEvent(self, event):
        
        self.updateAllLinks()
        QtGui.QGraphicsView.mouseMoveEvent(self, event)
   

    def updateAllNodes(self):
        '''
        Refresh all Nodes
        '''
        for n in self.nodes.values():
            n.update()
            
    def updateAllLinks(self):
        '''
        Refresh all Links
        '''
        for e in self.links.values():
            e.update()
            e.adjust()
            
    def updateAll(self):
        '''
        Refresh all Items
        # see if there is a auto way to updateall (updateScene()?)
        '''
        self.updateAllNodes()
        self.updateAllLinks()
 

    def getnodes(self):
        
        minX, maxX = -300, 300
        minY, maxY = -200, 200
        
        switchdpid = []
        for i in switches.keys():
            i = dpid_to_str(i)
            switchdpid.append(i)
            if i in self.nodes.keys():
                pass
            else:
                self.nodes[i] = Node("switch", i)
                self.topoScene.addItem(self.nodes[i])
                self.nodes[i].setPos(randint(minX,maxX), randint(minY, maxY))
        hostm = []
        for i in mac_map.keys():
            j = i.toStr()
            hostm.append(j)
            if j in self.nodes.keys():
                pass
            else:
                self.nodes[j] = Node("host", j)
                self.topoScene.addItem(self.nodes[j])
                self.nodes[j].setPos(randint(minX,maxX), randint(minY, maxY))
        
        temp = switchdpid + hostm
        for i in self.nodes.keys():
            if i not in temp:
                
                self.topoScene.removeItem(self.nodes[i])
                
                del self.nodes[i]

    def getlinks(self):
        
        for i in self.links.keys():
            self.links[i].isexist = False
        
        for i in mac_map.keys():
            j = i.toStr()
            sw = mac_map[i][0]
            port = mac_map[i][1]
            dpid = dpid_to_str(sw.dpid)
            if (dpid, j) in self.links.keys():
                self.links[(dpid, j)].isexist = True
                self.links[(dpid, j)].adjust()
                self.links[(j, dpid)].isexist = True
                self.links[(j, dpid)].adjust()
                
                
            else:
                self.links[(dpid, j)] = Link(self.nodes[dpid], self.nodes[j], port, None)
                self.topoScene.addItem(self.links[(dpid, j)])
                self.links[(j, dpid)] = Link(self.nodes[j], self.nodes[dpid], None, port)
                self.topoScene.addItem(self.links[(j, dpid)])
        
        for i in switches.values():
            for j in switches.values():
                if i == j:
                    pass
                else:
                    port = adjacency[i][j]
                    idpid = dpid_to_str(i.dpid)
                    jdpid = dpid_to_str(j.dpid)
                    if port is not None:
                        if (idpid, jdpid) in self.links.keys():
                            self.links[(idpid, jdpid)].adjust()
                            self.links[(idpid, jdpid)].isexist = True
                        else:
                            self.links[(idpid, jdpid)] = Link(self.nodes[idpid], self.nodes[jdpid], port, None)
                            self.topoScene.addItem(self.links[(idpid, jdpid)])
                    
        for i in self.links.keys():
            if self.links[i].isexist == False:
                self.topoScene.removeItem(self.links[i])
                del self.links[i]
            else:
                pass


class InfoWidget(QtGui.QListView):
    def __init__(self, parent = None):
        QtGui.QWidget.__init__(self, parent)
        self.vbox = QtGui.QVBoxLayout()
        self.label = QtGui.QLabel("switches port status")
        self.textfile = QtGui.QTextBrowser()
        self.refresh = QtGui.QPushButton("Refresh")

        
        self.testflag = 0
        
        """
        QtCore.Qt.AlignHCenter set widget in zhongjian
        """
        self.vbox.addWidget(self.label, 0, QtCore.Qt.AlignHCenter)
        self.vbox.addWidget(self.textfile)
        self.vbox.addWidget(self.refresh, 0, QtCore.Qt.AlignHCenter)
        self.setLayout(self.vbox)

        self.textfile.append("click refresh button to get port status information")
        
        
        
        self.connect(self.refresh, QtCore.SIGNAL('clicked()'), self.inforefresh)
        
    def inforefresh(self):
        
        
        global guiflag
        global guiinfo
        global guicon
        self.textfile.clear()
        for dpid in guicon.keys():
            guicon[dpid].send(of.ofp_stats_request(body = of.ofp_port_stats_request()))
            while not guiflag:
                pass
            info = "switch:" + str(dpid)
            self.textfile.append(info)
            self.textfile.append(guiinfo)
            guiinfo = ""
            guiflag = False

def stat_monitor():
  while True:
    time.sleep(5)
    for dpid in guicon.keys():
        if dpid is not None:
          
          guicon[dpid].send(of.ofp_stats_request(body = of.ofp_port_stats_request()))
	  #time.sleep(5) #calculate the use of bandwidth of each switch's port every 5 seconds

pox = None
        
def guithread():
  global pox
  app = QtGui.QApplication(sys.argv)
  pox = MainWindow()
  pox.show()

  sys.exit(app.exec_())


def launch ():
  core.registerNew(l2_multi)
  handle = handlemulticast()
  
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
  core.openflow.addListenerByName("PortStatsReceived", _handle_port_stats)

  thread.start_new_thread(run,())
  thread.start_new_thread(guithread,())
  thread.start_new_thread(stat_monitor,())  


