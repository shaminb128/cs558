# Copyright 2012 James McCauley
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
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    log.debug("output a packet to all ports. Packet src = " + str(packet.src) + "; packet dst = " + str(packet.dst) + "; packet in_port = " +str(packet_in.in_port));
    #self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """
    # Learn the port for the source MAC
    if packet.src not in self.mac_to_port:
      log.debug("=================> learning: adding mac_to_port_entry: src = " + str(packet.src) + "; in_port = " + str(packet_in.in_port))
      self.mac_to_port[packet.src] = packet_in.in_port

    #if the port associated with the destination MAC of the packet is known:
    if packet.dst in self.mac_to_port:
      log.debug("this packet is know, with dst " + str(packet.dst))
      # Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port[packet.dst])
    else:
      # Flood the packet out everything but the input port
      log.debug("this packet is NOT known, with dst " + str(packet.dst))
      self.resend_packet(packet_in, of.OFPP_ALL)

  def flow_redirect (self, packet, packet_in):
    if packet.src not in self.mac_to_port:
      log.debug("==========> adding mac_to_port_entry: src = " + str(packet.src) + "; in_port = " + str(packet_in.in_port))
      self.mac_to_port[packet.src] = packet_in.in_port
    
    if packet.dst == EthAddr("00:15:17:5d:13:6c"):
      log.debug("packet destination is node2, redirecting to node3...")
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 1200
      msg.hard_timeout = 3600
      msg.buffer_id = packet_in.buffer_id
      msg.priority = 65535
      msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:15:17:5d:33:64")))
      msg.actions.append(of.ofp_action_output(port = 3))
      # msg.data = event.ofp
      log.debug("==========> Installing flow... src = " + str(packet.src) + "; dest = " + str(packet.dst) + "; port = 3")
      #packet.dst = EthAddr("00:15:17:57:c6:f1")
      self.connection.send(msg)
      # self.resend_packet(packet_in, 3)
    elif packet.dst in self.mac_to_port:
      log.debug("==========> Installing flow... src = " + str(packet.src) + "; dest = " + str(packet.dst) + "; port = " + str(self.mac_to_port[packet.dst]))
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 1200
      msg.hard_timeout = 3600
      msg.buffer_id = packet_in.buffer_id
      msg.actions.append(of.ofp_action_output(port = self.mac_to_port[packet.dst]))
      self.connection.send(msg)
    else:
      self.resend_packet(packet_in, of.OFPP_ALL)
      

  def flow_accelerated (self, packet, packet_in):
    """
    Implement flow-accelerated behavior
    """
    # Learn the port for the source MAC
#    log.debug(str(packet_in))
#    if packet_in.in_port == 3 or packet_in.in_port == 2:
#     return
    if packet.src not in self.mac_to_port:
      log.debug("==========> adding mac_to_port_entry: src = " + str(packet.src) + "; in_port = " + str(packet_in.in_port))
      self.mac_to_port[packet.src] = packet_in.in_port

    #if the port associated with the destination MAC of the packet is known:
    if packet.dst in self.mac_to_port:
      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)
      log.debug("==========> Installing flow... src = " + str(packet.src) + "; dest = " + str(packet.dst) + "; port = " + str(self.mac_to_port[packet.dst]))
      # Maybe the log statement should have source/destination/port?
      msg = of.ofp_flow_mod()
      
      ## Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      msg.idle_timeout = 1200
      msg.hard_timeout = 3600
      msg.buffer_id = packet_in.buffer_id
      #
      #< Add an output action, and send -- similar to resend_packet() >
      msg.actions.append(of.ofp_action_output(port = self.mac_to_port[packet.dst]))
      self.connection.send(msg)

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      # log.debug("flooding... this packet is NOT known, with dst " + str(packet.dst))
      self.resend_packet(packet_in, of.OFPP_ALL)












  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    # self.act_like_hub(packet, packet_in)
    # self.act_like_switch(packet, packet_in)
    # self.flow_accelerated(packet, packet_in)
    self.flow_redirect(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
