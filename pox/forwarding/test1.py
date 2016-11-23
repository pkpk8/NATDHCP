#!/usr/bin/pythonfrompox.coreimportcore
#-*-encoding:utf-8-*-
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
log=core.getLogger()

class ConnectionUp(Event):
	def __init__(self,connection,ofp):
		Event.__init__(self)
		self.connection=connection
		self.dpid=connection.dpid
		self.ofp=ofp
		
class ConnectionDown(Event):
	def __init__(self,connection,ofp):
		Event.__init__(self)
		self.connection=connection
		self.dpid=connection.dpid
		
class PortStatus(Event):
	def __init__(self,connection,ofp):
		Event.__init__(self)
		self.connection=connection
		self.dpid=connection.dpid
		self.ofp=ofp
		self.modified=ofp.reason==of.OFPPR_MODIFY
		self.added=ofp.reason==of.OFPPR_ADD
		self.deleted=ofp.reaspn==of.OFPPR_DELETE
		self.port=ofp.desc.port_no

		
class MyComponent(object):
	def __init__(self):
		core.openflow.addListeners(self)
	#处理连接开启事件
	def _handle_ConnectionUp(self,event):
		ConnectionUp(event.connection,event.ofp)
		log.info("Switch %s has come up.",dpid_to_str(event.dpid))
	#处理连接关闭事件
	def _handle_ConnectionDown(self,event):
		ConnectionDown(event.connection,event.dpid)
		log.info("Switch %s has	shutdown.",dpid_to_str(event.dpid))
		
	def _handle_PortStatus(self,event):
		if event.added:
			action="added"
		elif event.deleted:
			action="removed"
		else:
			action="modified"
		print "Port %s on Switch %s has been %s." %(event.port,event.dpid,action)	
		
def launch():
	core.registerNew(MyComponent)
		
		







