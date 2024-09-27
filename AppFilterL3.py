from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import struct
import socket


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.h1_ip = "10.0.0.1"
        self.h2_ip = "10.0.0.2"
        self.h3_ip = "10.0.0.3"
        self.h1_to_h2_sent = False
        self.h2_to_h1_sent = False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype != ether_types.ETH_TYPE_IP:
            # Ignore non-IP packets
            return

        # Manually parse the IP header
        ip_header = pkt.protocols[1]
        ip_header_data = msg.data[14:34]  # IP header is 20 bytes long, starting after the Ethernet header
        ip_header_unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header_data)
        src_ip = socket.inet_ntoa(ip_header_unpacked[8])
        dst_ip = socket.inet_ntoa(ip_header_unpacked[9])

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src_ip, dst_ip, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth.src] = in_port

        if dst_ip == self.h3_ip:
            # Drop packets to h3
            self.logger.info("Dropping packet to h3")
            return

        if dst_ip == "255.255.255.255":
            # Allow broadcast packets
            out_port = ofproto.OFPP_FLOOD
        elif (src_ip == self.h1_ip and dst_ip == self.h2_ip and not self.h1_to_h2_sent):
            out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
            self.h1_to_h2_sent = True
        elif (src_ip == self.h2_ip and dst_ip == self.h1_ip and not self.h2_to_h1_sent):
            out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
            self.h2_to_h1_sent = True
        else:
            self.logger.info("Dropping packet not allowed by rules")
            return

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src, ipv4_src=src_ip, ipv4_dst=dst_ip)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)