# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# você não pode usar este arquivo exceto em conformidade com a Licença.
# Você pode obter uma cópia da Licença em
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# A menos que exigido por lei aplicável ou acordado por escrito, o software
# distribuído sob a Licença é distribuído "COMO ESTÁ", SEM GARANTIAS
# OU CONDIÇÕES DE QUALQUER TIPO, expressas ou implícitas.
# Veja a Licença para o idioma específico que rege permissões e
# limitações sob a Licença.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp


class L3Filter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Definindo os endereços IP de h1 e h2
    ALLOWED_IP_PAIRS = {
        ('10.0.0.1', '10.0.0.2'),  # h1 <-> h2
        ('10.0.0.2', '10.0.0.1')   # h2 <-> h1
    }

    def __init__(self, *args, **kwargs):
        super(L3Filter, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Instalar entrada de fluxo table-miss que envia pacotes para o controlador
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

        # Log do tipo de pacote recebido
        self.logger.info("Pacote recebido: eth_type=0x%04x", eth.ethertype)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignorar pacotes LLDP
            return

        # Manipular pacotes ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt.opcode == arp.ARP_REQUEST or arp_pkt.opcode == arp.ARP_REPLY:
                self.logger.info("Processando pacote ARP: %s -> %s", arp_pkt.src_ip, arp_pkt.dst_ip)
                self.handle_arp(datapath, in_port, eth, arp_pkt)
            return  # Após processar ARP, não precisa continuar

        # Manipular pacotes IPv4
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst

                # Verificar se o par de IPs está na lista de permitidos
                if (src_ip, dst_ip) in self.ALLOWED_IP_PAIRS:
                    self.logger.info("Permitido: %s -> %s", src_ip, dst_ip)

                    # Aprender o mapeamento MAC -> Porta
                    src = eth.src
                    dst = eth.dst
                    dpid = format(datapath.id, "d").zfill(16)
                    self.mac_to_port.setdefault(dpid, {})
                    self.mac_to_port[dpid][src] = in_port

                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    actions = [parser.OFPActionOutput(out_port)]

                    # Instalar fluxo para permitir tráfego futuro entre h1 e h2
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip)
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)

                    # Enviar o pacote para a porta de saída
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=msg.data)
                    datapath.send_msg(out)
                    return
                else:
                    self.logger.info("Bloqueado: %s -> %s", src_ip, dst_ip)
                    # Não instalar fluxo, descartando o pacote
                    return

        # Para pacotes que não são ARP ou IP, descartar
        self.logger.info("Pacote não IP e não ARP descartado.")
        return

    def handle_arp(self, datapath, in_port, eth, arp_pkt):
        """
        Manipula pacotes ARP para permitir a comunicação entre h1 e h2.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Aprender o mapeamento MAC -> Porta para ARP
        src_mac = arp_pkt.src_mac
        src_ip = arp_pkt.src_ip
        self.mac_to_port.setdefault(format(datapath.id, "d").zfill(16), {})
        self.mac_to_port[format(datapath.id, "d").zfill(16)][src_mac] = in_port

        # Criar correspondência para responder ao ARP
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Verificar se o ARP é para h1 ou h2
            if arp_pkt.dst_ip in ['10.0.0.1', '10.0.0.2']:
                # Encontrar o MAC correspondente ao dst_ip
                dst_mac = None
                for mac, port in self.mac_to_port[format(datapath.id, "d").zfill(16)].items():
                    if port == in_port and mac != src_mac:
                        dst_mac = mac
                        break
                if dst_mac:
                    # Construir pacote ARP Reply
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        src=eth.dst,
                        dst=eth.src
                    ))
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=eth.dst,
                        src_ip=arp_pkt.dst_ip,
                        dst_mac=eth.src,
                        dst_ip=arp_pkt.src_ip
                    ))
                    arp_reply.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER,
                                              actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    self.logger.info("Enviado ARP Reply: %s -> %s", arp_pkt.dst_ip, arp_pkt.src_ip)
