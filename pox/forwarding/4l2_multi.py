#!/usr/bin/env python2
#-*-encoding:utf-8-*-
# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
from pox.openflow.libopenflow_01 import *
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
from pox.lib.packet import *
from pox.lib.addresses import *
import time
import socket
import threading
import thread



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

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4

#************************************************** by zlk ********************************************
ip_entry = []
SERVER_IP = "192.168.1.110"
SERVER_IP2 = "10.0.0.110"
global SERVER_SW_PORT,OVS_MAC,SW_IP,SW_KEY
SERVER_CONTROLLER_PORT = 5560
OVS_IP = "192.168.1.1"
OVS_MAC2 = "2A:EF:FE:9A:43:E2"
OVS_MAC124 = "E6:D1:8E:C7:3A:A2"
SW_IP2 = "10.0.0.200"
SW_IP124 = "10.0.0.124"
SW_PORT = 5561
RTP_PORT = 5004

OVS_LIST = [('00-00-00-00-00-02','2','10.0.0.200','2A:EF:FE:9A:43:E2'),('00-00-00-00-01-24','292','10.0.0.124','E6:D1:8E:C7:3A:A2')]
SW_DPID = OVS_LIST[0][0]
SW_KEY = OVS_LIST[0][1]
SW_IP = OVS_LIST[0][2]
OVS_MAC = OVS_LIST[0][3]

#*********************************************** end by zlk ********************************************


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
    if adjacency[b[0]][a[0]] != b[1]:
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
    self.path = path

# by zxch
class HostNew (Event):
  """
  Fired when a new host found
  """
  def __init__ (self, hostmac, switch, port, connection, srcip):
    self.hostmac = hostmac
    self.switch = switch
    self.port = port
    self.connection = connection
    self.srcip = srcip

class HostChange (Event):
  """
  Fired when a host port changed
  """
  def __init__ (self, hostmac, switch, port, connection):
    self.hostmac = hostmac
    self.switch = switch
    self.port = port
    self.connection = connection
# end by zxch



# ***************************************************** by zlk *******************************************************
class ClientNew (Event):
  """
  Fired when a new host found
  """
  def __init__ (self,videoid,clientip):
    self.clientip = clientip
    self.videoid = videoid


class ClientOld (Event):
  """
  Fired when an old host found
  """
  def __init__ (self,clientip,videoid):
    self.clientip = clientip
    self.videoid = videoid

class RtpVideo (Event):
  """
  Fired when rtp video stream comes
  """
  def __init__ (self, hostmac, switch, port, connection, srcip,clientmac,dstip):
    self.hostmac = hostmac
    self.switch = switch
    self.port = port
    self.connection = connection
    self.srcip = srcip
    self.clientmac = clientmac
    self.dstip = dstip


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
    #print match.tp_src
    #print '######################################'
    if (str(switch) == SW_DPID and msg.match.dl_type == 0x0800 and msg.match.nw_proto == 17 and (msg.match.tp_dst==8080 or msg.match.tp_dst==5004)):
      print "Path install" 
    else: 
      switch.connection.send(msg)	    
   
#***************************************************** end by zlk ****************************************************

  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      msg.priority = 35534
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
        msg.priority = 35534
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
      msg.priority = 35534
      self.connection.send(msg)
      

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        msg.priority = 35534
        self.connection.send(msg)

    packet = event.parsed

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
      if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].dpid), oldloc[1],
                  dpid_to_str(   loc[0].dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        # Hopefully, this is a packet we're flooding because we didn't
        # know the destination, and not because it's somehow not on a
        # path that we expect it to be on.
        # If spanning_tree is running, we might check that this port is
        # on the spanning tree (it should be).
        if packet.dst in mac_map:
          # Unfortunately, we know the destination.  It's possible that
          # we learned it while it was in flight, but it's also possible
          # that something has gone wrong.
          log.warning("Packet from %s to known destination %s arrived "
                      "at %s.%i without flow", packet.src, packet.dst,
                      dpid_to_str(self.dpid), event.port)



    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)

     # by zxch
      if isinstance(packet.next, ipv4):
	log.debug("IP %s => %s", str(packet.next.srcip), str(packet.next.dstip))
	if (str(packet.next.srcip) != OVS_IP and packet.next.srcip not in ip_entry):
	  if (str(packet.next.srcip) == SERVER_IP and packet.next.srcip not in ip_entry):
	    #print "Server is up"
	    #SERVER_SW_PORT = event.port
	    #print "SERVER_SW_PORT"
	    #print SERVER_SW_PORT
	    ip_entry.append(packet.next.srcip)
	  else:
	    #print "Install new host IP"
	    ip_entry.append(packet.next.srcip)
	    if SERVER_IP in     ip_entry:
	      #print "Server starts video transmission"
	      core.l2_multi.raiseEvent(HostNew, packet.src, loc[0], loc[1], self.connection, packet.next.srcip)
      elif isinstance(packet, arp):
	log.debug("ARP %s %s => %s", {arp.REQUEST:"request", arp.REPLY:"reply"}.get(packet.opcode, 
	          'op:%i' % (packet.opcode,)), str(packet.protosrc), str(packet.protodst))
        # end by zxch

      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:

# ******************** by zlk ********************************************

# Video stream from server to switch and client
        if isinstance(packet.next, ipv4) and packet.next.srcip == SERVER_IP:
          if isinstance(packet.next.next, udp) and (packet.next.next.dstport ==5004 or packet.next.next.dstport ==8080):
            print "rtp video stream found"

            core.l2_multi.raiseEvent(RtpVideo, packet.src, loc[0], loc[1], self.connection, packet.next.srcip,packet.dst,packet.next.dstip)              
            print 'Video in_port:'
            print loc
           
#Video cache from switch to client
        elif isinstance(packet.next, ipv4) and packet.next.srcip == OVS_IP:
           if isinstance(packet.next.next, udp) and (packet.next.next.dstport == 5004 or packet.next.next.dstport ==8080):

            msg = of.ofp_flow_mod()
            msg.priority = 65535
            msg.match.dl_type = 0x0800
            msg.match.nw_proto = 17
            msg.match.in_port = 65534  
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            event.connection.send(msg) 
            
 # ******************************************* end by zlk *********************************************
        
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


class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
    HostNew,
    RtpVideo,
    ClientNew,
    ClientOld,
   
  ])

  def __init__ (self):
    # Listen to dependencies (specifying priority 0 for openflow)
    core.listen_to_dependencies(self, listen_args={'openflow':{'priority':0}})

  def _handle_openflow_discovery_LinkEvent (self, event):
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
        if sw is sw1 and port == l.port1: bad_macs.add(mac)
        if sw is sw2 and port == l.port2: bad_macs.add(mac)
      for mac in bad_macs:
        log.debug("Unlearned %s", mac)
        del mac_map[mac]

  def _handle_openflow_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)

  def _handle_openflow_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      #log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)

# by zxch
class HostHandle (object):
  def __init__(self):
    core.l2_multi.addListeners(self)

  def _handle_HostNew (self, event):
    print "Switch %s has come up a new host %s" %(event.switch, event.hostmac)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((SERVER_IP2, SERVER_CONTROLLER_PORT))
    log.debug("host ip is %s", str(event.srcip))
    s.send(str(event.srcip))
    s.close()


#************************************************** by zlk ********************************************
  def _handle_ClientNew (self, event):
    print "Switch has come up a new host %s" %(event.clientip)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((SERVER_IP2, SERVER_CONTROLLER_PORT))
    log.debug("host ip is %s", str(event.clientip))
    s.send(str(event.videoid)+'#'+str(event.clientip))
    s.close() 

  def _handle_ClientOld (self, event):
    print "Switch has come up an old host %s" %(event.clientip)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((SW_IP, SW_PORT))
    s.send('rtpplay'+'->'+str(event.clientip)+'->'+str(event.videoid))
    print 'rtpplay'+'->'+str(event.clientip)
    log.debug("rtpplay sent")
    s.close()
  
  def _handle_RtpVideo (self,event):
 
    print 'UDP finall out_port:'
    print mac_map[EthAddr(clientmac)]

    msg = of.ofp_flow_mod()
    msg.priority = 55535
    msg.match.dl_type = 0x0800
    msg.match.nw_proto = 17
    #msg.match.in_port = event.port
    msg.match.dl_src = event.hostmac
    msg.match.dl_dst = event.clientmac
    msg.match.nw_src = event.srcip
    msg.match.nw_dst = event.dstip
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(OVS_IP)))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(OVS_MAC)))
    msg.actions.append(of.ofp_action_output(port = OFPP_LOCAL))
    #event.connection.send(msg)
    core.openflow.connections[int(SW_KEY)].send(msg)
    print 'messege sent'

def run():
    print 'hello'
    time.sleep(6)
    print '[dpid] -> Switch:'
    print core.openflow.connections.keys()
    print switches

def fromDeviceManager():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port=40008
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((s.getsockname()[0],port))
    s.listen(5)
    while True:
            global clientmac
	    connection,address=s.accept()
	    buf=connection.recv(1024)
	    print buf
	    inf=buf.split('#')
	    videoid=inf[0]
	    clientmac=inf[1]
	    clientip=inf[2]
	    servermac=inf[3]
	    serverip=inf[4]
            num=inf[5]
            
            if num=='1':
               core.l2_multi.raiseEvent(ClientNew,videoid,clientip)        
               s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
               s1.connect((SW_IP, SW_PORT))
               s1.send("rtpdump"+"->"+videoid)
               log.debug("rtpdump sent")
               print 'rtpdump sent'
               s1.close()    
            else:
               core.l2_multi.raiseEvent(ClientOld,clientip,videoid)
    s.close()

#******************************************************end by zlk**************************************************

def launch ():
  core.registerNew(l2_multi)
  core.registerNew(HostHandle)
  
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)



  thread.start_new_thread(run,())
  thread.start_new_thread(fromDeviceManager,())
