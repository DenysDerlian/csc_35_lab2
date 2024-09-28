from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

# Define the main application class
class L3Filter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Define allowed IP pairs for communication
    ALLOWED_IP_PAIRS = {
        ('10.0.0.1', '10.0.0.2'),  # h1 -> h2
        ('10.0.0.2', '10.0.0.1')   # h2 -> h1
    }

    def __init__(self, *args, **kwargs):
        super(L3Filter, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    # Event handler for switch features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Install flow to allow ARP packets and flood them
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 100, match_arp, actions_arp)

        # Install table-miss flow entry for IP packets
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Function to add a flow entry
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

    # Event handler for packet-in events
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Handle IPv4 packets
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst

                # Check if the IP pair is allowed
                if (src_ip, dst_ip) in self.ALLOWED_IP_PAIRS:
                    self.logger.info("Allowed: %s -> %s", src_ip, dst_ip)

                    # Learn the MAC to port mapping
                    src_mac = eth.src
                    dst_mac = eth.dst
                    dpid = datapath.id
                    self.mac_to_port.setdefault(dpid, {})
                    self.mac_to_port[dpid][src_mac] = in_port

                    if dst_mac in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst_mac]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    actions = [parser.OFPActionOutput(out_port)]

                    # Install flow to allow future traffic between h1 and h2
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip)
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)

                    # Send the packet out to the output port
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        return
                    data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return
                else:
                    self.logger.info("Blocked: %s -> %s", src_ip, dst_ip)
                    # Do not install flow, drop the packet
                    return

        # For non-IP packets, drop them
        self.logger.info("Non-IP packet dropped: eth_type=0x%04x", eth.ethertype)
        return