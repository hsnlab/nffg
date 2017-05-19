# Copyright 2017 Janos Czentye, Balazs Nemeth, Balazs Sonkoly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Abstract class and implementation for basic operations with a single NF-FG, such
as building, parsing, processing NF-FG, helper functions, etc.
"""
import copy
import itertools
import logging
import math
import pprint
import re
from collections import defaultdict
from copy import deepcopy

import networkx
from networkx.exception import NetworkXError

from nffg_elements import *

VERSION = "1.0"


class AbstractNFFG(object):
  """
  Abstract class for managing single NF-FG data structure.

  The NF-FG data model is described in YANG. This class provides the
  interfaces with the high level data manipulation functions.
  """

  ##############################################################################
  # NFFG specific functions
  ##############################################################################

  def add_nf (self):
    """
    Add a single NF node to the NF-FG.
    """
    raise NotImplementedError

  def add_sap (self):
    """
    Add a single SAP node to the NF-FG.
    """
    raise NotImplementedError

  def add_infra (self):
    """
    Add a single infrastructure node to the NF-FG.
    """
    raise NotImplementedError

  def add_link (self, src, dst):
    """
    Add a static or dynamic infrastructure link to the NF-FG.

    :param src: source port
    :param dst: destination port
    """
    raise NotImplementedError

  def add_sglink (self, src, dst):
    """
    Add an SG link to the NF-FG.

    :param src: source port
    :param dst: destination port
    """
    raise NotImplementedError

  def add_req (self, src, dst):
    """
    Add a requirement link to the NF-FG.

    :param src: source port
    :param dst: destination port
    """
    raise NotImplementedError

  def add_node (self, node):
    """
    Add a single node to the NF-FG.

    :param node: node object
    """
    raise NotImplementedError

  def del_node (self, id):
    """
    Remove a single node from the NF-FG.

    :param id: id of the node
    """
    raise NotImplementedError

  def add_edge (self, src, dst, link):
    """
    Add an edge to the NF-FG.

    :param src: source port
    :param dst: destination port
    :param link: link object
    """
    raise NotImplementedError

  def del_edge (self, src, dst):
    """
    Remove an edge from the NF-FG.

    :param src: source port
    :param dst: destination port
    """
    raise NotImplementedError

  ##############################################################################
  # General functions for create/parse/dump/convert NFFG
  ##############################################################################

  @classmethod
  def parse (cls, data):
    """
    General function for parsing data as a new :any::`NFFG` object and return
    with its reference.

    :param data: raw data
    :type data: str
    :return: parsed NFFG as an XML object
    :rtype: :class:`Virtualizer`
    """
    raise NotImplementedError

  def dump (self):
    """
    General function for dumping :any::`NFFG` according to its format to
    plain text.

    :return: plain text representation
    :rtype: str
    """
    raise NotImplementedError


class NFFG(AbstractNFFG):
  """
  Internal NFFG representation based on networkx.
  """
  # Default domain value
  DEFAULT_DOMAIN = NodeInfra.DEFAULT_DOMAIN
  """Default domain value"""
  # Infra types
  TYPE_INFRA_SDN_SW = NodeInfra.TYPE_SDN_SWITCH
  TYPE_INFRA_EE = NodeInfra.TYPE_EE
  TYPE_INFRA_STATIC_EE = NodeInfra.TYPE_STATIC_EE
  TYPE_INFRA_BISBIS = NodeInfra.TYPE_BISBIS
  # Node types
  TYPE_INFRA = Node.INFRA
  TYPE_NF = Node.NF
  TYPE_SAP = Node.SAP
  # Link types
  TYPE_LINK_STATIC = Link.STATIC
  TYPE_LINK_DYNAMIC = Link.DYNAMIC
  TYPE_LINK_SG = Link.SG
  TYPE_LINK_REQUIREMENT = Link.REQUIREMENT
  # Port constants
  PORT_ROLE_CONSUMER = Port.ROLE_CONSUMER
  PORT_ROLE_PROVIDER = Port.ROLE_PROVIDER
  # Mapping mode operations
  MODE_ADD = "ADD"
  MODE_DEL = "DELETE"
  MODE_REMAP = "REMAP"
  # Element operation
  OP_CREATE = Element.OP_CREATE
  OP_REPLACE = Element.OP_REPLACE
  OP_MERGE = Element.OP_MERGE
  OP_REMOVE = Element.OP_REMOVE
  OP_DELETE = Element.OP_DELETE
  # Element status
  STATUS_INIT = Element.STATUS_INIT
  STATUS_PENDING = Element.STATUS_PENDING
  STATUS_DEPLOY = Element.STATUS_DEPLOY
  STATUS_RUN = Element.STATUS_RUN
  STATUS_STOP = Element.STATUS_STOP
  STATUS_FAIL = Element.STATUS_FAIL
  # Mapping process status
  MAP_STATUS_SKIPPED = "SKIPPED"  # mark NFFG as skipped for ESCAPE

  version = VERSION

  def __init__ (self, id=None, name=None, service_id=None, mode=None,
                metadata=None, status=None, version=VERSION):
    """
    Init.

    :param id: optional NF-FG identifier (generated by default)
    :type id: str or int
    :param name: optional NF-FG name (generated by default)
    :type name: str
    :param service_id: service id this NFFG is originated from
    :type service_id: str or int
    :param mode: describe how to handle the defined elements (default: ADD)
    :type mode: str
    :param metadata: optional metadata for NFFG
    :type metadata: dict
    :param status: optional info for NFFG
    :type status: str
    :param version: optional version (default: 1.0)
    :type version: str
    :return: None
    """
    super(NFFG, self).__init__()
    self.network = networkx.MultiDiGraph()
    self.id = str(id) if id is not None else Element.generate_unique_id()
    self.name = name
    self.service_id = service_id
    self.metadata = OrderedDict(metadata if metadata else ())
    self.mode = mode
    self.status = status
    self.version = version

  ##############################################################################
  # Element iterators
  ##############################################################################

  @property
  def nfs (self):
    """
    Iterate over the NF nodes.

    :return: iterator of NFs
    :rtype: collections.Iterator
    """
    return (node for id, node in self.network.nodes_iter(data=True) if
            node.type == Node.NF)

  @property
  def saps (self):
    """
    Iterate over the SAP nodes.

    :return: iterator of SAPs
    :rtype: collections.Iterator
    """
    return (node for id, node in self.network.nodes_iter(data=True) if
            node.type == Node.SAP)

  @property
  def infras (self):
    """
    Iterate over the Infra nodes.

    :return: iterator of Infra node
    :rtype: collections.Iterator
    """
    return (node for id, node in self.network.nodes_iter(data=True) if
            node.type == Node.INFRA)

  @property
  def links (self):
    """
    Iterate over the link edges.

    :return: iterator of edges
    :rtype: collections.Iterator
    """
    return (link for src, dst, link in self.network.edges_iter(data=True) if
            link.type == Link.STATIC or link.type == Link.DYNAMIC)

  @property
  def sg_hops (self):
    """
    Iterate over the service graph hops.

    :return: iterator of SG edges
    :rtype: collections.Iterator
    """
    return (link for s, d, link in self.network.edges_iter(data=True) if
            link.type == Link.SG)

  @property
  def reqs (self):
    """
    Iterate over the requirement edges.

    :return: iterator of requirement edges
    :rtype: collections.Iterator
    """
    return (link for s, d, link in self.network.edges_iter(data=True) if
            link.type == Link.REQUIREMENT)

  ##############################################################################
  # Magic functions mostly for dict specific behaviour
  ##############################################################################

  def __str__ (self):
    """
    Return the string representation.

    :return: string representation
    :rtype: str
    """
    return "NFFG(id=%s name=%s, version=%s)" % (
      self.id, self.name, self.version)

  def __contains__ (self, item):
    """
    Return True if item exist in the NFFG, False otherwise.

    :param item: node object or id
    :type item: :any:`Node` or str
    :return: item is in the NFFG
    :rtype: bool
    """
    if isinstance(item, Node):
      item = item.id
    return item in self.network

  def __iter__ (self, data=False):
    """
    Return an iterator over the nodes.

    :param data: If True return a two-tuple of node and node data dictionary
    :type data: bool
    :return: An iterator over nodes.
    """
    return self.network.nodes_iter(data=data)

  def __len__ (self):
    """
    Return the number of nodes.

    :return: number of nodes
    :rtype: int
    """
    return len(self.network)

  def __getitem__ (self, item):
    """
    Return the object given by the id: item.

    :param item: node id
    :return: node object
    """
    return self.network.node[item]

  ##############################################################################
  # Builder design pattern related functions
  ##############################################################################

  def add_node (self, node):
    """
    Add a Node to the structure.

    :param node: a Node object
    :type node: :any:`Node`
    :return: None
    """
    self.network.add_node(node.id)
    self.network.node[node.id] = node

  def del_node (self, node):
    """
    Remove the node from the structure.

    :param node: node id or node object or a port object of the node
    :type node: str or :any:`Node` or :any`Port`
    :return: the actual node is found and removed or not
    :rtype: bool
    """
    try:
      if isinstance(node, Node):
        node = node.id
      elif isinstance(node, Port):
        node = node.node.id
      self.network.remove_node(node)
      return True
    except NetworkXError:
      # There was no node in the graph
      return False

  def add_edge (self, src, dst, link):
    """
    Add an Edge to the structure.

    :param src: source node id or Node object or a Port object
    :type src: str or :any:`Node` or :any`Port`
    :param dst: destination node id or Node object or a Port object
    :type dst: str or :any:`Node` or :any`Port`
    :param link: edge data object
    :type link: :any:`Link`
    :return: None
    """
    if isinstance(src, Node):
      src = src.id
    elif isinstance(src, Port):
      src = src.node.id
    if isinstance(dst, Node):
      dst = dst.id
    elif isinstance(dst, Port):
      dst = dst.node.id
    self.network.add_edge(src, dst, key=link.id)
    self.network[src][dst][link.id] = link

  def del_edge (self, src, dst, id=None):
    """
    Remove the edge(s) between two nodes.

    :param src: source node id or Node object or a Port object
    :type src: str or :any:`Node` or :any`Port`
    :param dst: destination node id or Node object or a Port object
    :type dst: str or :any:`Node` or :any`Port`
    :param id: unique id of the edge (otherwise remove all)
    :type id: str or int
    :return: the actual node is found and removed or not
    :rtype: bool
    """
    try:
      if isinstance(src, Node):
        src = src.id
      elif isinstance(src, Port):
        src = src.node.id
      if isinstance(dst, Node):
        dst = dst.id
      elif isinstance(dst, Port):
        dst = dst.node.id
      if id is not None:
        self.network.remove_edge(src, dst, key=id)
      else:
        self.network[src][dst].clear()
      return True
    except NetworkXError:
      # There was no node in the graph
      return False

  def add_nf (self, nf=None, id=None, name=None, func_type=None, dep_type=None,
              cpu=None, mem=None, storage=None, delay=None, bandwidth=None):
    """
    Add a Network Function to the structure.

    :param nf: add this explicit NF object instead of create one
    :type nf: :any:`NodeNF`
    :param id: optional id
    :type id: str or ints
    :param name: optional name
    :type name: str
    :param func_type: functional type (default: "None")
    :type func_type: str
    :param dep_type: deployment type (default: "None")
    :type dep_type: str
    :param cpu: CPU resource
    :type cpu: float
    :param mem: memory resource
    :type mem: float
    :param storage: storage resource
    :type storage: float
    :param delay: delay property of the Node
    :type delay: float
    :param bandwidth: bandwidth property of the Node
    :type bandwidth: float
    :return: newly created node
    :rtype: :any:`NodeNF`
    """
    if nf is None:
      if any(i is not None for i in (cpu, mem, storage, delay, bandwidth)):
        res = NodeResource(cpu=cpu, mem=mem, storage=storage, delay=delay,
                           bandwidth=bandwidth)
      else:
        res = None
      nf = NodeNF(id=id, name=name, func_type=func_type, dep_type=dep_type,
                  res=res)
    self.add_node(nf)
    return nf

  def add_sap (self, sap_obj=None, id=None, name=None, binding=None, sap=None,
               technology=None, delay=None, bandwidth=None, cost=None,
               controller=None, orchestrator=None, l2=None, l4=None,
               metadata=None):
    """
    Add a Service Access Point to the structure.

    :param sap_obj: add this explicit SAP object instead of create one
    :type sap_obj: :any:`NodeSAP`
    :param id: optional id
    :type id: str or int
    :param name: optional name
    :type name: str
    :param binding: interface binding
    :type binding: str
    :param sap: inter-domain SAP identifier
    :type sap: str
    :param technology: technology
    :type technology: str
    :param delay: delay
    :type delay: float
    :param bandwidth: bandwidth
    :type bandwidth: float
    :param cost: cost
    :type cost: str
    :param controller: controller
    :type controller: str
    :param orchestrator: orchestrator
    :type orchestrator: str
    :param l2: l2
    :param l2: str
    :param l4: l4
    :type l4: str
    :param metadata: metadata related to Node
    :type metadata: dict
    :return: newly created node
    :rtype: :any:`NodeSAP`
    """
    if sap_obj is None:
      sap_obj = NodeSAP(id=id, name=name, binding=binding, metadata=metadata)
    self.add_node(sap_obj)
    return sap_obj

  def add_infra (self, infra=None, id=None, name=None, domain=None,
                 infra_type=None, cpu=None, mem=None, storage=None, delay=None,
                 bandwidth=None):
    """
    Add an Infrastructure Node to the structure.

    :param infra: add this explicit Infra object instead of create one
    :type infra: :any:`NodeInfra`
    :param id: optional id
    :type id: str or int
    :param name: optional name
    :type name: str
    :param domain: domain of the Infrastructure Node (default: None)
    :type domain: str
    :param infra_type: type of the Infrastructure Node (default: 0)
    :type infra_type: int or str
    :param cpu: CPU resource
    :type cpu: float
    :param mem: memory resource
    :type mem: float
    :param storage: storage resource
    :type storage: float
    :param delay: delay property of the Node
    :type delay: float
    :param bandwidth: bandwidth property of the Node
    :type bandwidth: float
    :return: newly created node
    :rtype: :any:`NodeInfra`
    """
    if infra is None:
      if any(i is not None for i in (cpu, mem, storage, delay, bandwidth)):
        res = NodeResource(cpu=cpu, mem=mem, storage=storage,
                           bandwidth=bandwidth, delay=delay)
      else:
        res = None
      infra = NodeInfra(id=id, name=name, domain=domain, infra_type=infra_type,
                        res=res)
    self.add_node(infra)
    return infra

  def add_link (self, src_port, dst_port, link=None, id=None, dynamic=False,
                backward=False, delay=None, bandwidth=None):
    """
    Add a Link to the structure.

    :param link: add this explicit Link object instead of create one
    :type link: :any:`EdgeLink`
    :param src_port: source port
    :type src_port: :any:`Port`
    :param dst_port: destination port
    :type dst_port: :any:`Port`
    :param id: optional link id
    :type id: str or int
    :param backward: the link is a backward link compared to an another Link
    :type backward: bool
    :param delay: delay resource
    :type delay: float
    :param dynamic: set the link dynamic (default: False)
    :type dynamic: bool
    :param bandwidth: bandwidth resource
    :type bandwidth: float
    :return: newly created edge
    :rtype: :any:`EdgeLink`
    """
    if link is None:
      type = Link.DYNAMIC if dynamic else Link.STATIC
      link = EdgeLink(src=src_port, dst=dst_port, type=type, id=id,
                      backward=backward, delay=delay, bandwidth=bandwidth)
    else:
      link.src, link.dst = src_port, dst_port
    self.add_edge(src_port.node, dst_port.node, link)
    return link

  def add_undirected_link (self, port1, port2, p1p2id=None, p2p1id=None,
                           dynamic=False, delay=None, bandwidth=None):
    """
    Add two Links to the structure, in both directions.

    :param port1: source port
    :type port1: :any:`Port`
    :param port2: destination port
    :type port2: :any:`Port`
    :param p1p2id: optional link id from port1 to port2
    :type p1p2id: str or int
    :param p2p1id: optional link id from port2 to port1
    :type p2p1id: str or int
    :param delay: delay resource of both links
    :type delay: float
    :param dynamic: set the link dynamic (default: False)
    :type dynamic: bool
    :param bandwidth: bandwidth resource of both links
    :type bandwidth: float
    :return: newly created edge tuple in (p1->p2, p2->p1)
    :rtype: :any:(`EdgeLink`, `EdgeLink`)
    """
    p1p2Link = self.add_link(port1, port2, id=p1p2id, dynamic=dynamic,
                             backward=False, delay=delay, bandwidth=bandwidth)
    p2p1Link = self.add_link(port2, port1, id=p2p1id, dynamic=dynamic,
                             backward=True, delay=delay, bandwidth=bandwidth)
    return p1p2Link, p2p1Link

  def add_sglink (self, src_port, dst_port, hop=None, id=None, flowclass=None,
                  tag_info=None, delay=None, bandwidth=None):
    """
    Add a SG next hop edge to the structure.

    :param hop: add this explicit SG Link object instead of create one
    :type hop: :any:`EdgeSGLink`
    :param src_port: source port
    :type src_port: :any:`Port`
    :param dst_port: destination port
    :type dst_port: :any:`Port`
    :param id: optional link id
    :type id: str or int
    :param flowclass: flowclass of SG next hop link
    :type flowclass: str
    :param tag_info: tag info
    :type tag_info: str
    :param delay: delay requested on link
    :type delay: float
    :param bandwidth: bandwidth requested on link
    :type bandwidth: float
    :return: newly created edge
    :rtype: :any:`EdgeSGLink`
    """
    if hop is None:
      hop = EdgeSGLink(src=src_port, dst=dst_port, id=id, flowclass=flowclass,
                       tag_info=tag_info, bandwidth=bandwidth, delay=delay)
    self.add_edge(src_port.node, dst_port.node, hop)
    return hop

  def add_req (self, src_port, dst_port, req=None, id=None, delay=None,
               bandwidth=None, sg_path=None):
    """
    Add a requirement edge to the structure.

    :param req: add this explicit Requirement Link object instead of create one
    :type req: :any:`EdgeReq`
    :param src_port: source port
    :type src_port: :any:`Port`
    :param dst_port: destination port
    :type dst_port: :any:`Port`
    :param id: optional link id
    :type id: str or int
    :param delay: delay resource
    :type delay: float
    :param bandwidth: bandwidth resource
    :type bandwidth: float
    :param sg_path: list of ids of sg_links represents end-to-end requirement
    :type sg_path: list or tuple
    :return: newly created edge
    :rtype: :any:`EdgeReq`
    """
    if req is None:
      req = EdgeReq(src=src_port, dst=dst_port, id=id, delay=delay,
                    bandwidth=bandwidth, sg_path=sg_path)
    self.add_edge(src_port.node, dst_port.node, req)
    return req

  def add_metadata (self, name, value):
    """
    Add metadata with the given `name`.

    :param name: metadata name
    :type name: str
    :param value: metadata value
    :type value: str
    :return: the :class:`NFFG` object to allow function chaining
    :rtype: :class:`NFFG`
    """
    self.metadata[name] = value
    return self

  def get_metadata (self, name):
    """
    Return the value of metadata.

    :param name: name of the metadata
    :type name: str
    :return: metadata value
    :rtype: str
    """
    return self.metadata.get(name)

  def del_metadata (self, name):
    """
    Remove the metadata from the :class:`NFFG`. If no metadata is given all the
    metadata will be removed.

    :param name: name of the metadata
    :type name: str
    :return: removed metadata or None
    :rtype: str or None
    """
    if name is None:
      self.metadata.clear()
    else:
      return self.metadata.pop(name, None)

  def dump (self):
    """
    Convert the NF-FG structure to a NFFGModel format and return the plain
    text representation.

    :return: text representation
    :rtype: str
    """
    # Create the model
    nffg = NFFGModel(id=self.id, name=self.name, service_id=self.service_id,
                     version=self.version, mode=self.mode,
                     metadata=self.metadata)
    # Load Infras
    for infra in self.infras:
      nffg.node_infras.append(infra)
    # Load SAPs
    for sap in self.saps:
      nffg.node_saps.append(sap)
    # Load NFs
    for nf in self.nfs:
      nffg.node_nfs.append(nf)
    # Load Links
    for link in self.links:
      nffg.edge_links.append(link)
    # Load SG next hops
    for hop in self.sg_hops:
      nffg.edge_sg_nexthops.append(hop)
    # Load Requirements
    for req in self.reqs:
      nffg.edge_reqs.append(req)
    # Dump
    return nffg.dump()

  def dump_to_json (self):
    """
    Return the NF-FG structure in JSON compatible format.

    :return: NFFG as a valid JSON
    :rtype: dict
    """
    return json.loads(self.dump())

  @classmethod
  def parse (cls, raw_data):
    """
    Read the given JSON object structure and try to convert to an NF-FG
    representation as an :class:`NFFG`

    :param raw_data: raw NF-FG description as a string
    :type raw_data: str
    :return: the parsed NF-FG representation
    :rtype: :class:`NFFG`
    """
    # Parse text
    model = NFFGModel.parse(raw_data)
    # Create new NFFG
    nffg = NFFG(id=model.id, name=model.name, service_id=model.service_id,
                version=model.version, mode=model.mode, metadata=model.metadata)
    # Load Infras
    for infra in model.node_infras:
      nffg.add_node(infra)
    # Load SAPs
    for sap in model.node_saps:
      nffg.add_node(sap)
    # Load NFs
    for nf in model.node_nfs:
      nffg.add_node(nf)
    # Load Links
    for link in model.edge_links:
      if link.src.node.type == NFFG.TYPE_NF or \
            link.dst.node.type == NFFG.TYPE_NF:
        link.type = str(NFFG.TYPE_LINK_DYNAMIC)
      nffg.add_edge(link.src.node, link.dst.node, link)
    # Load SG next hops
    for hop in model.edge_sg_nexthops:
      nffg.add_edge(hop.src.node, hop.dst.node, hop)
    # Load Requirements
    for req in model.edge_reqs:
      nffg.add_edge(req.src.node, req.dst.node, req)
    return nffg

  @staticmethod
  def parse_from_file (path):
    """
    Parse NFFG from file given by the path.

    :param path: file path
    :type path: str
    :return: the parsed NF-FG representation
    :rtype: :class:`NFFG`
    """
    with open(path) as f:
      return NFFG.parse(f.read())

  ##############################################################################
  # Helper functions
  ##############################################################################

  def is_empty (self):
    """
    Return True if the NFFG contains no Node.

    :return: :class:`NFFG` object is empty or not
    :rtype: bool
    """
    return len(self.network) == 0

  def is_infrastructure (self):
    """
    Return True if the NFFG is an infrastructure view with Infrastructure nodes.

    :return: the NFFG is an infrastructure view
    :rtype: bool
    """
    return sum([1 for i in self.infras]) != 0

  def is_SBB (self):
    """
    Return True if the topology detected as a trivial SingleBiSBiS view,
    which consist of only one Infra node with type: ``BiSBiS``.

    :return: SingleBiSBiS or not
    :rtype: bool
    """
    itype = [i.infra_type for i in self.infras]
    return len(itype) == 1 and itype.pop() == self.TYPE_INFRA_BISBIS

  def is_bare (self):
    """
    Return True if the topology does not contain any NF or flowrules need to
    install or remap.

    :return: is bare topology or not
    :rtype: bool
    """
    # If there is no VNF
    if len([v for v in self.nfs]) == 0:
      fr_sum = sum([sum(1 for fr in i.ports.flowrules) for i in self.infras])
      # And there is no flowrule in the ports
      if fr_sum == 0:
        sg_sum = len([sg for sg in self.sg_hops])
        # And there is not SG hop
        if sg_sum == 0:
          e2e_sum = len([sg for sg in self.reqs])
          if e2e_sum == 0:
            return True
    return False

  def is_virtualized (self):
    """
    Return True if the topology contains at least one virtualized BiSBiS node.

    :return: contains any NF or not
    :rtype: bool
    """
    return len([i for i in self.infras if
                i.infra_type not in (self.TYPE_INFRA_SDN_SW, self.TYPE_INFRA_EE,
                                     self.TYPE_INFRA_STATIC_EE)]) > 0

  def real_neighbors_iter (self, node):
    """
    Return with an iterator over the id of neighbours of the given Node not
    counting the SG and E2E requirement links.

    :param node: examined :any:`Node` id
    :type node: str or int
    :return: iterator over the filtered neighbors
    :rtype: iterator
    """
    return (v for u, v, link in self.network.out_edges_iter(node, data=True)
            if link.type in (self.TYPE_LINK_STATIC, self.TYPE_LINK_DYNAMIC))

  def real_out_edges_iter (self, node):
    """
    Return with an iterator over the out edge data of the given Node not
    counting the SG and E2E requirement links.

    :param node: examined :any:`Node` id
    :type node: str or int
    :return: iterator over the filtered neighbors (u,v,d)
    :rtype: iterator
    """
    return (data for data in self.network.out_edges_iter(node, data=True)
            if data[2].type in (self.TYPE_LINK_STATIC, self.TYPE_LINK_DYNAMIC))

  def duplicate_static_links (self):
    """
    Extend the NFFG model with backward links for STATIC links to fit for the
    orchestration algorithm.

    STATIC links: infra-infra, infra-sap

    :return: NF-FG with the duplicated links for function chaining
    :rtype: :class:`NFFG`
    """
    # Create backward links
    backwards = [EdgeLink(src=link.dst, dst=link.src, id=str(link.id) + "-back",
                          backward=True, delay=link.delay,
                          bandwidth=link.bandwidth) for u, v, link in
                 self.network.edges_iter(data=True) if link.type == Link.STATIC]
    # Add backward links to the NetworkX structure in a separate step to
    # avoid the link reduplication caused by the iterator based for loop
    for link in backwards:
      self.add_edge(src=link.src, dst=link.dst, link=link)
    return self

  def merge_duplicated_links (self):
    """
    Detect duplicated STATIC links which both are connected to the same
    Port/Node and have switched source/destination direction to fit for the
    simplified NFFG dumping.

    Only leaves one of the links, but that's not defined which one.

    :return: NF-FG with the filtered links for function chaining
    :rtype: :class:`NFFG`
    """
    # Collect backward links
    backwards = [(src, dst, key) for src, dst, key, link in
                 self.network.edges_iter(keys=True, data=True) if (
                   link.type == Link.STATIC or link.type == Link.DYNAMIC) and
                 link.backward is True]
    # Delete backwards links
    for link in backwards:
      self.network.remove_edge(*link)
    return self

  def adjacent_sghops (self, nf_id):
    """
    Returns a list with the outbound or inbound SGHops from an NF.

    :param nf_id: nf node id
    :type nf_id: :class:`NodeNf`
    :return: list
    """
    return [sg for sg in self.sg_hops if sg.src.node.id == nf_id or \
            sg.dst.node.id == nf_id]

  def infra_neighbors (self, node_id):
    """
    Return an iterator for the Infra nodes which are neighbours of the given
    node.

    :param node_id: infra node
    :type node_id: :any:`NodeInfra`
    :return: iterator for the list of Infra nodes
    """
    return (self.network.node[id] for id in self.network.neighbors_iter(node_id)
            if self.network.node[id].type == Node.INFRA)

  def running_nfs (self, infra_id):
    """
    Return an iterator for the NodeNFs which are mapped to the given Infra node.

    :param infra_id: infra node identifier
    :type infra_id: :any: `NodeInfra`
    :return: iterator for the currently running NodeNFs
    """
    return (self.network.node[id] for id in
            self.network.neighbors_iter(infra_id) if
            self.network.node[id].type == Node.NF)

  def get_domain_of_nf (self, nf_id):
    bb = [bb for bb in self.infra_neighbors(nf_id)]
    return bb.pop().domain if len(bb) == 1 else None

  def clear_links (self, link_type):
    """
    Remove every specific Link from the NFFG defined by given ``type``.

    :param link_type: link type defined in :class:`NFFG`
    :type link_type: str
    :return: None
    """
    return self.network.remove_edges_from(
      [(u, v, link.id) for u, v, link in self.network.edges_iter(data=True) if
       link.type == link_type])

  def clear_nodes (self, node_type):
    """
    Remove every specific Node from the NFFG defined by given ``type``.

    :param node_type: node type defined in :class:`NFFG`
    :type node_type: str
    :return: None
    """
    return self.network.remove_nodes_from(
      [id for id, node in self.network.nodes_iter(data=True) if
       node.type == node_type])

  def copy (self):
    """
    Return the deep copy of the NFFG object.

    :return: deep copy
    :rtype: :class:`NFFG`
    """
    copy = NFFG(id=self.id, name=self.name, version=self.version,
                mode=self.mode, metadata=self.metadata.copy(),
                status=self.status)
    copy.network = self.network.copy()
    return copy

  def calculate_available_link_res (self, sg_hops_to_be_ignored, mode=MODE_ADD):
    """
    Calculates available bandwidth on all the infrastructure links.
    Stores them in 'availbandwidth' field of the link objects.
    Modifies the NFFG instance. 
    
    :param sg_hops_to_be_ignored: container for ID-s which should be ignored
    :type sg_hops_to_be_ignored: collections.Iterable
    :param mode: Determines whether the flowrules should be considered.
    :type mode: str
    :return: None
    """
    # set availbandwidth to the maximal value
    for i, j, k, d in self.network.edges_iter(data=True, keys=True):
      if d.type == 'STATIC':
        setattr(self.network[i][j][k], 'availbandwidth', d.bandwidth)
    # subtract the reserved link and internal (inside Infras) bandwidth
    if mode == self.MODE_ADD:
      for d in self.infras:
        for p in d.ports:
          for fr in p.flowrules:
            if fr.id not in sg_hops_to_be_ignored and fr.bandwidth is not None:
              # Flowrules are cummulatively subtracted from the switching 
              # capacity of the node.
              d.availres['bandwidth'] -= fr.bandwidth
              if d.availres['bandwidth'] < 0:
                raise RuntimeError("The node bandwidth of %s got below zero "
                                   "during available resource calculation!" %
                                   d.id)
      # Get all the mapped paths of all SGHops from the NFFG
      sg_map = NFFGToolBox.get_all_sghop_info(self, return_paths=True)
      for sg_hop_id, data in sg_map.iteritems():
        src, dst, flowclass, bandwidth, delay, path = data
        if bandwidth is not None:
          for link in path:
            link.availbandwidth -= bandwidth
            if link.availbandwidth < 0:
              raise RuntimeError(
                "The link bandwidth of %s got below zero during"
                "available resource calculation!" % link.id)

  def calculate_available_node_res (self, vnfs_to_be_left_in_place={},
                                    mode=MODE_ADD):
    """
    Calculates available computation and networking resources of the nodes of
    NFFG. Creates a NodeResource instance for each NodeInfra to store the 
    available resources in the 'availres' attribute added by this fucntion.

    :param vnfs_to_be_left_in_place: NodeNF.id-s to be ignored subtraction.
    :type vnfs_to_be_left_in_place: dict
    :param mode: Determines whether the running NFs should be considered.
    :return: None
    """
    # add available res attribute to all Infras and subtract the running
    # NFs` resources from the given max res
    for n in self.infras:
      setattr(self.network.node[n.id], 'availres',
              copy.deepcopy(self.network.node[n.id].resources))
      if mode == self.MODE_ADD:
        for vnf in self.running_nfs(n.id):
          # if a VNF needs to be left in place, then it is still mapped by the 
          # mapping process, but with placement criteria, so its resource 
          # requirements will be subtracted during the greedy process.
          if vnf.id not in vnfs_to_be_left_in_place:
            try:
              newres = self.network.node[n.id].availres.subtractNodeRes(
                self.network.node[vnf.id].resources,
                self.network.node[n.id].resources)
            except RuntimeError:
              raise RuntimeError(
                "Infra node`s resources are expected to represent its maximal "
                "capabilities."
                "The NodeNF(s) running on Infra node %s, use(s)more resource "
                "than the maximal." % n.id)
          else:
            try:
              newres = self.network.node[n.id].availres.subtractNodeRes(
                vnfs_to_be_left_in_place[vnf.id].resources,
                self.network.node[n.id].resources)
            except RuntimeError:
              raise RuntimeError("VNF %s cannot be kept on host %s with "
                                 "increased resource requirements due to not "
                                 "enough available resources!" % (vnf.id, n.id))

          self.network.node[n.id].availres = newres

  def del_flowrules_of_SGHop (self, hop_id_to_del):
    """
    Deletes all flowrules, which belong to a given SGHop ID. 
    Compares based on Flowrule.ID and SGHop.ID they should be identical only 
    for the corresponding Flowrules.

    :param hop_id_to_del: collection of flowrule ids need to be deleted
    :type hop_id_to_del: list
    :return: None
    """
    for n in self.infras:
      for p in n.ports:
        for fr in p.flowrules:
          if fr.id == hop_id_to_del:
            p.del_flowrule(id=fr.id)


class NFFGToolBox(object):
  """
  Helper functions for NFFG handling operations, etc.
  """

  ##############################################################################
  # ------------------ Splitting/Merging-related functions ---------------------
  ##############################################################################

  @staticmethod
  def detect_domains (nffg):
    """
    Return with the set of detected domains in the given ``nffg``.

    :param nffg: observed NFFG
    :type nffg: :class:`NFFG`
    :return: set of the detected domains
    :rtype: set
    """
    return {infra.domain for infra in nffg.infras}

  @staticmethod
  def recreate_inter_domain_SAPs (nffg, log=logging.getLogger("SAP-recreate")):
    """
    Search for possible inter-domain ports examining ports' metadata and
    recreate associated SAPs.

    :param nffg: observed NFFG
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: modified NFFG
    :rtype: :class:`NFFG`
    """
    for infra in nffg.infras:
      for port in infra.ports:
        # Check ports of remained Infra's for SAP ports
        if port.get_property("type") == "inter-domain":
          # Found inter-domain SAP port
          log.debug("Found inter-domain SAP port: %s" % port)
          adj_nodes = [v for u, v, l in nffg.real_out_edges_iter(infra.id)
                       if l.src.id == port.id]
          if len(adj_nodes) != 0:
            log.debug("Detected port connects to other node: %s!. Skip..." %
                      adj_nodes)
            continue
          # Copy optional SAP metadata as special id or name
          # Create default SAP object attributes
          if port.has_property("sap"):
            sap_id = port.get_property("sap")
            log.debug("Detected dynamic 'sap' property: %s in port: %s" %
                      (sap_id, port))
          elif port.sap is not None:
            sap_id = port.sap
            log.debug("Detected static 'sap' value: %s in port: %s" %
                      (sap_id, port))
          else:
            log.warning(
              "%s is detected as inter-domain port, but 'sap' metadata is not "
              "found! Using 'name' metadata as fallback..." % port)
            sap_id = port.get_property("name")
          if port.has_property('name'):
            sap_name = port.get_property("name")
            log.debug('Using dynamic name: %s for inter-domain port' % sap_name)
          else:
            sap_name = port.name
            log.debug('Using static name: %s for inter-domain port' % sap_name)
          # Add SAP to splitted NFFG
          if sap_id in nffg:
            log.warning("%s is already in the splitted NFFG. Skip adding..." %
                        nffg[sap_id])
            continue
          sap = nffg.add_sap(id=sap_id, name=sap_name)
          # Add port to SAP port number(id) is identical with the Infra's port
          sap_port = sap.add_port(id=port.id, name=port.name,
                                  properties=port.properties.copy(),
                                  sap=port.sap,
                                  capability=port.capability,
                                  technology=port.technology,
                                  delay=port.delay,
                                  bandwidth=port.bandwidth, cost=port.cost,
                                  controller=port.controller,
                                  orchestrator=port.orchestrator, l2=port.l2,
                                  l4=port.l4,
                                  metadata=port.metadata.copy())
          for l3 in port.l3:
            sap_port.l3.append(l3.copy())
          # Connect SAP to Infra
          nffg.add_undirected_link(port1=port, port2=sap_port)
          log.debug(
            "Add inter-domain SAP: %s with port: %s" % (sap, sap_port))
    return nffg

  @staticmethod
  def trim_orphaned_nodes (nffg, log=logging.getLogger("TRIM")):
    """
    Remove orphaned nodes from given :class:`NFFG`.

    :param nffg: observed NFFG
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: trimmed NFFG
    :rtype: :class:`NFFG`
    """
    detected = set()
    for u, v, link in nffg.network.edges_iter(data=True):
      detected.add(link.src.node.id)
      detected.add(link.dst.node.id)
    orphaned = {n for n in nffg} - detected
    for node in orphaned:
      log.warning("Found orphaned node: %s! Remove from sliced part." %
                  nffg[node])
      nffg.del_node(node)
    if orphaned:
      log.debug("Remained nodes: %s" % [n for n in nffg])
    return nffg

  @classmethod
  def merge_new_domain (cls, base, nffg, log=logging.getLogger("MERGE")):
    """
    Merge the given ``nffg`` into the ``base`` NFFG using the given domain name.

    :param base: base NFFG object
    :type base: :class:`NFFG`
    :param nffg: updating information
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    # Get new domain name
    domain = cls.detect_domains(nffg=nffg)
    if len(domain) == 0:
      log.error("No domain detected in new %s!" % nffg)
      return
    if len(domain) > 1:
      log.warning("Multiple domain name detected in new %s!" % nffg)
      return
    # Copy infras
    log.debug("Merge domain: %s resource info into %s..." % (domain.pop(),
                                                             base.id))
    # Check if the infra with given id is already exist in the base NFFG
    for infra in nffg.infras:
      if infra.id not in base:
        c_infra = base.add_infra(infra=deepcopy(infra))
        log.debug("Copy infra node: %s" % c_infra)
      else:
        log.warning("Infra node: %s does already exist in %s. Skip adding..." %
                    (infra, base))
    # Copy NFs
    for nf in nffg.nfs:
      if nf.id not in base:
        c_nf = base.add_nf(nf=deepcopy(nf))
        log.debug("Copy NF node: %s" % c_nf)
      else:
        log.warning("NF node: %s does already exist in %s. Skip adding..." %
                    (nf, base))
    # Copy SAPs
    for sap_id in [s.id for s in nffg.saps]:
      if sap_id in [s.id for s in base.saps]:
        # Found inter-domain SAP
        log.debug("Found Inter-domain SAP: %s" % sap_id)
        # Search outgoing links from SAP, should be only one
        b_links = [l for u, v, l in base.real_out_edges_iter(sap_id)]
        if len(b_links) < 1:
          log.warning(
            "SAP is not connected to any node! Maybe you forgot to call "
            "duplicate_static_links?")
          return
        elif 1 < len(b_links):
          log.warning(
            "Inter-domain SAP should have one and only one connection to the "
            "domain! Using only the first connection.")
          continue
        # Get inter-domain port in base NFFG
        domain_port_dov = b_links[0].dst
        sap_port_dov = b_links[0].src
        log.debug("Found inter-domain port: %s" % domain_port_dov)
        # Search outgoing links from SAP, should be only one
        n_links = [l for u, v, l in nffg.real_out_edges_iter(sap_id)]
        if len(n_links) < 1:
          log.warning(
            "SAP is not connected to any node! Maybe you forgot to call "
            "duplicate_static_links?")
          return
        elif 1 < len(n_links):
          log.warning(
            "Inter-domain SAP should have one and only one connection to the "
            "domain! Using only the first connection.")
          continue
        # Get port and Infra id's in nffg NFFG
        p_id = n_links[0].dst.id
        n_id = n_links[0].dst.node.id
        # Get the inter-domain port from already copied Infra
        domain_port_nffg = base.network.node[n_id].ports[p_id]
        sap_port_nffg = n_links[0].src
        log.debug("Found inter-domain port: %s" % domain_port_nffg)

        # # If the two resource value does not match
        # if sap_port_dov.delay != sap_port_nffg.delay:
        #   if sap_port_dov.delay is None:
        #     # If first is None the other can not be None
        #     s_delay = sap_port_nffg.delay
        #   elif sap_port_nffg.delay is None:
        #     # If second is None the other can not be None
        #     s_delay = sap_port_dov.delay
        #   else:
        #     # Both values are valid, but different
        #     s_delay = max(sap_port_dov.delay, sap_port_nffg.delay)
        #     log.warning(
        #       "Inter-domain delay values (%s, %s) are set but do not match!"
        #       " Use max: %s" % (sap_port_dov.delay, sap_port_nffg.delay,
        #                         s_delay))
        # else:
        #   # Both value match: ether valid values or Nones --> choose first
        # value
        #   s_delay = sap_port_dov.delay
        #
        # # If the two resource value does not match
        # if sap_port_dov.bandwidth != sap_port_nffg.bandwidth:
        #   if sap_port_dov.bandwidth is None:
        #     # If first is None the other can not be None
        #     s_bandwidth = sap_port_nffg.bandwidth
        #   elif sap_port_nffg.bandwidth is None:
        #     # If second is None the other can not be None
        #     s_bandwidth = sap_port_dov.bandwidth
        #   else:
        #     # Both values are valid, but different
        #     s_bandwidth = min(sap_port_dov.bandwidth,
        #                       sap_port_nffg.bandwidth)
        #     log.warning(
        #       "Inter-domain bandwidth values (%s, %s) are set but do not
        # match!"
        #       " Use min: %s" % (sap_port_dov.bandwidth,
        #                         sap_port_nffg.bandwidth, s_bandwidth))
        # else:
        #   # Both value match: ether valid values or Nones --> choose first
        # value
        #   s_bandwidth = sap_port_dov.bandwidth
        #
        # log.debug("Detected inter-domain resource values: delay: %s, "
        #           "bandwidth: %s" % (s_delay, s_bandwidth))

        # Copy inter-domain port properties/values for redundant storing
        if len(domain_port_nffg.properties) > 0:
          domain_port_dov.properties.update(domain_port_nffg.properties)
          log.debug("Copy inter-domain port properties: %s" %
                    domain_port_dov.properties)
        elif len(domain_port_dov.properties) > 0:
          domain_port_nffg.properties.update(domain_port_dov.properties)
          log.debug("Copy inter-domain port properties: %s" %
                    domain_port_nffg.properties)
        # Ensure to add sap tag to inter domain ports
        if 'sap' not in domain_port_dov.properties:
          domain_port_dov.add_property("sap", sap_id)
        if 'sap' not in domain_port_nffg.properties:
          domain_port_nffg.add_property("sap", sap_id)
        # Signal Inter-domain port type
        domain_port_dov.add_property("type", "inter-domain")
        domain_port_nffg.add_property("type", "inter-domain")

        # Copy SAP port values into the infra ports
        domain_port_dov.name = sap_port_dov.name
        domain_port_dov.sap = sap_port_dov.sap
        domain_port_dov.capability = sap_port_dov.capability
        domain_port_dov.technology = sap_port_dov.technology
        domain_port_dov.delay = sap_port_dov.delay
        domain_port_dov.bandwidth = sap_port_dov.bandwidth
        domain_port_dov.cost = sap_port_dov.cost
        domain_port_dov.controller = sap_port_dov.controller
        domain_port_dov.orchestrator = sap_port_dov.orchestrator
        domain_port_dov.l2 = sap_port_dov.l2
        domain_port_dov.l4 = sap_port_dov.l4
        for l3 in sap_port_dov.l3:
          domain_port_dov.l3.append(l3.copy())
        domain_port_dov.metadata.update(sap_port_dov.metadata)

        domain_port_nffg.name = sap_port_nffg.name
        domain_port_nffg.sap = sap_port_nffg.sap
        domain_port_nffg.capability = sap_port_nffg.capability
        domain_port_nffg.technology = sap_port_nffg.technology
        domain_port_nffg.delay = sap_port_nffg.delay
        domain_port_nffg.bandwidth = sap_port_nffg.bandwidth
        domain_port_nffg.cost = sap_port_nffg.cost
        domain_port_nffg.controller = sap_port_nffg.controller
        domain_port_nffg.orchestrator = sap_port_nffg.orchestrator
        domain_port_nffg.l2 = sap_port_nffg.l2
        domain_port_nffg.l4 = sap_port_nffg.l4
        for l3 in sap_port_nffg.l3:
          domain_port_nffg.l3.append(l3.copy())
        domain_port_nffg.metadata.update(sap_port_nffg.metadata)

        # Delete both inter-domain SAP and links connected to them
        base.del_node(sap_id)
        nffg.del_node(sap_id)

        # Add the inter-domain links for both ways
        l1, l2 = base.add_undirected_link(
          p1p2id="inter-domain-link-%s" % sap_id,
          p2p1id="inter-domain-link-%s-back" % sap_id,
          port1=domain_port_dov,
          port2=domain_port_nffg)
        # Set delay/bandwidth values for outgoing link port1 -> port2
        l1.delay = domain_port_dov.delay
        l1.bandwidth = domain_port_dov.bandwidth
        # Set delay/bandwidth values for outgoing link port2 -> port2
        l2.delay = domain_port_nffg.delay
        l2.bandwidth = domain_port_nffg.bandwidth

      else:
        # Normal SAP --> copy SAP
        c_sap = base.add_sap(sap_obj=deepcopy(nffg.network.node[sap_id]))
        log.debug("Copy SAP: %s" % c_sap)
    # Copy remaining links which should be valid
    for u, v, link in nffg.network.edges_iter(data=True):
      src_port = base.network.node[u].ports[link.src.id]
      dst_port = base.network.node[v].ports[link.dst.id]
      c_link = deepcopy(link)
      c_link.src = src_port
      c_link.dst = dst_port
      base.add_link(src_port=src_port, dst_port=dst_port, link=c_link)
      log.debug("Copy Link: %s" % c_link)
    log.debug("Domain merging has been finished!")
    # Return the updated NFFG
    return base

  @staticmethod
  def strip_domain (nffg, domain, log=logging.getLogger("STRIP")):
    """
    Trim the given :class:`NFFG` and leave only the nodes belong to the given
    ``domain``.

    ..warning::
      No inter-domain SAP recreation will be performed after the trim!

    :param nffg: mapped NFFG object
    :type nffg: :class:`NFFG`
    :param domain: extracted domain name
    :type domain: str
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: stripped NFFG
    :rtype: :class:`NFFG`
    """
    log.info("Strip domain in %s" % nffg)
    nffg = nffg.copy()
    # Collect every node which not in the domain
    deletable = set()
    for infra in nffg.infras:
      # Domains representations based on infras
      if infra.domain == domain:
        # Skip current domains infra
        continue
      # Mark the infra as deletable
      deletable.add(infra.id)
      # Look for orphan NF ans SAP nodes which connected to this deletable infra
      for node_id in nffg.real_neighbors_iter(infra.id):
        if nffg[node_id].type in (NFFG.TYPE_SAP, NFFG.TYPE_NF):
          deletable.add(node_id)
    log.debug("Nodes marked for deletion: %s" % deletable)
    nffg.network.remove_nodes_from(deletable)
    log.debug("Remained nodes: %s" % [n for n in nffg])
    return nffg

  @classmethod
  def split_into_domains (cls, nffg, log=logging.getLogger("SPLIT")):
    """
    Split given :class:`NFFG` into separate parts self._global_nffg on
    original domains.

    :param nffg: mapped NFFG object
    :type nffg: :class:NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: sliced parts as a list of (domain_name, nffg_part) tuples
    :rtype: list
    """
    splitted_parts = []

    log.info("Splitting NFFG: %s according to detected domains" % nffg)
    # Define DOMAIN names
    domains = cls.detect_domains(nffg=nffg)
    log.debug("Detected domains for splitting: %s" % domains)

    if len(domains) == 0:
      log.warning("No domain has been detected!")
      return splitted_parts

    # Checks every domain
    for domain in domains:
      log.info("Create slice for domain: %s" % domain)
      # Collect every node which not in the domain
      deletable = set()
      for infra in nffg.infras:
        # Domains representations based on infras
        if infra.domain == domain:
          # Skip current domains infra
          continue
        # Mark the infra as deletable
        deletable.add(infra.id)
        # Look for orphan NF ans SAP nodes which connected to this deletable
        # infra
        for node_id in nffg.real_neighbors_iter(infra.id):
          if nffg[node_id].type in (NFFG.TYPE_SAP, NFFG.TYPE_NF):
            deletable.add(node_id)
      log.debug("Nodes marked for deletion: %s" % deletable)

      log.debug("Clone NFFG...")
      # Copy the NFFG
      nffg_part = nffg.copy()
      # Set metadata
      nffg_part.name = domain
      # Delete needless nodes --> and as a side effect the connected links too
      log.debug("Delete marked nodes...")
      nffg_part.network.remove_nodes_from(deletable)
      if len(nffg_part):
        log.debug("Remained nodes: %s" % [n for n in nffg_part])
      else:
        log.debug("No node was remained after splitting!")
      splitted_parts.append((domain, nffg_part))

      log.debug(
        "Search for inter-domain SAP ports and recreate associated SAPs...")
      # Recreate inter-domain SAP
      cls.recreate_inter_domain_SAPs(nffg=nffg_part, log=log)

      # Check orphaned or not connected nodes and remove them
      log.debug("Trim orphaned nodes from splitted part...")
      cls.trim_orphaned_nodes(nffg=nffg_part, log=log)
      log.debug("Merge external ports into it's original SAP port...")
      cls.merge_external_ports(nffg=nffg_part, log=log)
    log.info("Splitting has been finished!")
    return splitted_parts

  @classmethod
  def split_nfs_by_domain (cls, nffg, nfs=None, log=logging.getLogger('SPLIT')):
    if nfs is None:
      nfs = [nfs.id for nfs in nffg.nfs]
    log.debug("Splitting nfs: %s by domains..." % nfs)
    domains = {}
    for nf in nfs:
      domain = nffg.get_domain_of_nf(nf_id=nf)
      if not domain:
        log.warning("Missing domain of nf: %s" % nf)
        continue
      if domain in domains:
        domains[domain].append(nf)
      else:
        domains[domain] = [nf]
    return domains

  @classmethod
  def recreate_missing_match_TAGs (cls, nffg, log=logging.getLogger("TAG")):
    """
    Recreate TAGs for flowrules forwarding traffic from a different domain.

    In case there is a hop in the service request mapped as a collocated link
    it might break down to multiple links/flowrules in a lower layer where the
    links are placed into different domains therefore the match/action field are
    created without tags because collocated links do not use tags by default.

    :param nffg: mapped NFFG object
    :type nffg: :any:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: None
    """
    log.debug("Recreate missing TAG matching fields...")
    for infra in nffg.infras:
      # Iterate over flowrules of the infra
      for flowrule in infra.flowrules():
        # Get the source in_port of the flowrule from match field
        splitted = flowrule.match.split(';', 1)
        in_port = splitted[0].split('=')[1]
        try:
          # Convert in_port to int if it is possible
          in_port = int(in_port)
        except ValueError:
          pass
        # If the port is an inter-domain port
        if infra.ports[in_port].get_property('type') == "inter-domain":
          log.debug("Found inter-domain port: %s", infra.ports[in_port])
          if len(splitted) > 1:
            # There is one or more TAG in match
            tags = splitted[1].split(';')
            found = False
            for tag in tags:
              try:
                vlan = tag.split('|')[-1]
              except ValueError:
                continue
              # Found a TAG with the vlan
              if vlan == str(flowrule.id):
                found = True
                break
            if found:
              # If found the appropriate TAG -> skip adding
              continue
          log.debug("TAG with vlan: %s is not found in %s!" % (flowrule.id,
                                                               flowrule))
          match_vlan = ";TAG=<None>|<None>|%s" % flowrule.id
          flowrule.match += match_vlan
          log.debug("Manually extended match field: %s" % flowrule.match)

  @classmethod
  def rewrite_interdomain_tags (cls, slices,
                                log=logging.getLogger("adaptation.TAG")):
    """
    Calculate and rewrite inter-domain tags.

    Inter-domain connections via inter-domain SAPs are harmonized
    here. The abstract tags in flowrules are rewritten to technology
    specific ones based on the information retrieved from inter-domain
    SAPs.

    :param slices: list of mapped :class:`NFFG` instances
    :type slices: list
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: list of NFFG structures with updated tags
    """
    log.debug("Calculating inter-domain tags...")

    for nffg in slices:
      log.debug("Processing domain %s" % nffg[0])
      # collect SAP ports of infra nodes
      sap_ports = []
      for sap in nffg[1].saps:
        sap_switch_links = [(u, v, link) for u, v, link in
                            nffg[1].network.edges_iter(data=True) if
                            sap.id in (u, v) and
                            link.type == NFFG.TYPE_LINK_STATIC]
        # sap_switch_links = [e for e in
        #                     nffg[1].network.edges_iter(data=True) if
        #                     sap.id in e]
        # list of e = (u, v, data)
        try:
          if sap_switch_links[0][0] == sap.id:
            sap_ports.append(sap_switch_links[0][2].dst)
          else:
            sap_ports.append(sap_switch_links[0][2].src)
        except IndexError:
          log.error(
            "Link for SAP: %s is not found." % sap)
          continue
      log.debug("SAP_PORTS: %s" % sap_ports)
      for infra in nffg[1].infras:
        # log.debug("Processing infra %s" % infra)
        for flowrule in infra.flowrules():
          for sap_port in sap_ports:
            # process inbound flowrules of SAP ports
            if re.search('in_port=', flowrule.match):
              in_port = re.sub(r'.*in_port=([^;]*).*', r'\1',
                               flowrule.match)
              if str(in_port) == str(sap_port.id):
                # found inbound rule
                log.debug("Found inbound flowrule (%s):\n %s"
                          % (flowrule.id, flowrule))
                if sap_port.sap is not None:
                  log.debug("Found inter-domain SAP port: %s, %s" %
                            (sap_port, sap_port.sap))
                  # rewrite TAG in match field
                  if not re.search(r'TAG', flowrule.match):
                    match_tag = ";TAG=<None>|<None>|%s" % flowrule.id
                    flowrule.match += match_tag
                    log.info("TAG conversion: extend match field in a "
                             "flowrule of infra %s" % infra.id)
                    log.info("updated flowrule (%s):\n %s"
                             % (flowrule.id, flowrule))
                else:
                  log.debug("Found user SAP port: %s" %
                            sap_port)
                  # remove TAG from match field
                  if re.search(r'TAG', flowrule.match):
                    flowrule.match = re.sub(r'(;TAG=[^;]*)', r'',
                                            flowrule.match)
                    log.info("TAG conversion: remove TAG match in a "
                             "flowrule of infra %s" % infra.id)
                    log.info("updated flowrule (%s):\n %s"
                             % (flowrule.id, flowrule))
            # process outbound flowrules of SAP ports
            if re.search('output=', flowrule.action):
              output = re.sub(r'.*output=([^;]*).*', r'\1',
                              flowrule.action)
              if str(output) == str(sap_port.id):
                # found outbound rule
                log.debug("Found outbound rule (%s):\n %s"
                          % (flowrule.id, flowrule))
                if sap_port.sap is not None:
                  log.debug("Found inter-domain SAP port: %s, %s" %
                            (sap_port, sap_port.sap))
                  # rewrite TAG in action field
                  if not re.search(r'TAG', flowrule.action):
                    push_tag = ";TAG=<None>|<None>|%s" % flowrule.id
                    flowrule.action += push_tag
                    log.info("TAG conversion: extend action field in a "
                             "flowrule of infra %s" % infra.id)
                    log.info("updated flowrule (%s):\n %s"
                             % (flowrule.id, flowrule))
                else:
                  log.debug("Found user SAP port: %s" %
                            sap_port)
                  # remove TAG from action field
                  if re.search(r';TAG', flowrule.action):
                    flowrule.action = re.sub(r'(;TAG=[^;]*)', r'',
                                             flowrule.action)
                    log.info("TAG conversion: remove TAG action in a "
                             "flowrule of infra %s" % infra.id)
                  # add UNTAG to action field
                  if not re.search(r'UNTAG', flowrule.action):
                    flowrule.action += ';UNTAG'
                    log.info("TAG conversion: add UNTAG action in a "
                             "flowrule of infra %s" % infra.id)
                    log.info("updated flowrule (%s):\n %s"
                             % (flowrule.id, flowrule))
    return slices

  @staticmethod
  def rebind_e2e_req_links (nffg, log=logging.getLogger("REBIND")):
    """
    Search for splitted requirement links in the NFFG. If a link connects
    inter-domain SAPs rebind the link as an e2e requirement link.

    :param nffg: splitted NFFG object
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: rebounded NFFG
    :rtype: :class:`NFFG`
    """
    log.debug(
      "Search for requirement link fragments to rebind as e2e requirement...")
    req_cache = []

    def __detect_connected_sap (port):
      """
      Detect if the given port is connected to a SAP.

      :param port: port object
      :type port: :any:`Port`
      :return: SAP port or None
      :rtype: :any:`Port`
      """
      connected_port = [l.dst for u, v, l in
                        nffg.real_out_edges_iter(port.node.id)
                        if str(l.src.id) == str(port.id)]
      # If the number of detected nodes is unexpected continue to the next req
      if len(connected_port) < 1:
        log.warning("Skip edge rebinding: No connected node is detected for "
                    "SAP port: %s" % port)
        return None
      elif len(connected_port) > 1:
        log.warning("Skip edge rebinding: Multiple connected nodes are "
                    "detected for SAP port: %s: %s!" % (port, connected_port))
        return None
      elif connected_port[0].node.type == NFFG.TYPE_SAP:
        return connected_port[0]
      else:
        return None

    for req in nffg.reqs:
      if req.src.node.type == NFFG.TYPE_SAP and \
            req.dst.node.type == NFFG.TYPE_SAP:
        log.debug("Skip rebinding: Detected %s is already an end-to-end link!" %
                  req)
        return nffg
        # Detect the node connected to the src port of req link
      src_sap_port = __detect_connected_sap(port=req.src)
      if src_sap_port:
        log.debug("Detected src SAP node: %s" % src_sap_port)
      else:
        continue
      # Detect the node connected to the dst port of req link
      dst_sap_port = __detect_connected_sap(port=req.dst)
      if dst_sap_port:
        log.debug("Detected dst SAP node: %s" % dst_sap_port)
      else:
        continue
      # Create e2e req link and store for rebinding
      e2e_req = req.copy()
      e2e_req.src = src_sap_port
      e2e_req.dst = dst_sap_port
      req_cache.append((req.src.node.id, req.dst.node.id, req.id, e2e_req))

    # Rebind marked Requirement links
    if not req_cache:
      log.debug("No requirement link has been rebounded!")
    else:
      for src, dst, id, e2e in req_cache:
        nffg.del_edge(src=src, dst=dst, id=id)
        nffg.add_edge(src=e2e.src, dst=e2e.dst, link=e2e)
        log.debug("Rebounded requirement link: %s" % e2e)
    # Return the rebounded NFFG
    return nffg

  ##############################################################################
  # ----------------------- Single BiSBiS view generation ----------------------
  ##############################################################################

  @staticmethod
  def generate_SBB_representation (nffg, add_sg_hops=False,
                                   log=logging.getLogger("SBB")):
    """
    Generate the trivial virtual topology a.k.a one BisBis or Single BisBis
    representation with calculated resources and transferred NF and SAP nodes.

    :param nffg: global resource
    :type nffg: :class:`NFFG`
    :param add_sg_hops: recreate SG hop links also (default: False)
    :type add_sg_hops: bool
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: single Bisbis representation
    :rtype: :class:`NFFG`
    """
    if nffg is None:
      log.error("Missing global resource info! Skip OneBisBis generation!")
      return None
    # Create Single BiSBiS NFFG
    log.debug("Generate trivial SingleBiSBiS NFFG based on %s:" % nffg)
    log.debug("START SBB generation...")
    sbb = NFFG(id="SingleBiSBiS", name="Single-BiSBiS-View")
    # Create the single BiSBiS infra
    sbb_infra = sbb.add_infra(id="SingleBiSBiS",
                              name="SingleBiSBiS",
                              domain=NFFG.DEFAULT_DOMAIN,
                              infra_type=NFFG.TYPE_INFRA_BISBIS)
    # Compute and add resources
    # Sum of available CPU
    try:
      sbb_infra.resources.cpu = sum(
        # If iterator is empty, sum got None --> TypeError thrown by sum
        (n.resources.cpu for n in nffg.infras if
         n.resources.cpu is not None) or None)
    except TypeError:
      sbb_infra.resources.cpu = None
    # Sum of available memory
    try:
      sbb_infra.resources.mem = sum(
        # If iterator is empty, sum got None --> TypeError thrown by sum
        (n.resources.mem for n in nffg.infras if
         n.resources.mem is not None) or None)
    except TypeError:
      sbb_infra.resources.mem = None
    # Sum of available storage
    try:
      sbb_infra.resources.storage = sum(
        # If iterator is empty, sum got None --> TypeError thrown by sum
        (n.resources.storage for n in nffg.infras if
         n.resources.storage is not None) or None)
    except TypeError:
      sbb_infra.resources.storage = None
    # Minimal available delay value of infras and links in DoV
    try:
      # Get the minimum delay in Dov to avoid false negative mapping result
      sbb_infra.resources.delay = min(itertools.chain(
        # If the chained iterators is empty --> ValueError thrown by sum
        (n.resources.delay for n in nffg.infras if
         n.resources.delay is not None),
        (l.delay for l in nffg.links if l.delay is not None)))
    except ValueError:
      sbb_infra.resources.delay = None
    # Maximum available bandwidth value of infras and links in DoV
    try:
      max_bw = max(itertools.chain(
        (n.resources.bandwidth for n in nffg.infras if
         n.resources.bandwidth is not None),
        (l.bandwidth for l in nffg.links if l.bandwidth is not None)))
      # Number of infras and links in DoV
      sum_infra_link = sum(1 for _ in itertools.chain(nffg.infras, nffg.links))
      # Overestimate switching capacity to avoid false positive mapping result
      sbb_infra.resources.bandwidth = max_bw * sum_infra_link
    except ValueError:
      sbb_infra.resources.bandwidth = None
    log.debug("Computed SingleBiBBiS resources: %s" % sbb_infra.resources)
    # Add supported types
    s_types = set()
    for infra in nffg.infras:
      s_types = s_types.union(infra.supported)
    sbb_infra.add_supported_type(s_types)
    log.debug("Added supported types: %s" % s_types)
    log.debug("Added Infra BiSBiS: %s" % sbb_infra)
    log.log(5, "SBB:\n%s" % sbb_infra.dump())
    # Add existing NFs
    for nf in nffg.nfs:
      c_nf = sbb.add_nf(nf=nf.copy())
      log.debug("Added NF: %s" % c_nf)
      log.log(5, "NF:\n%s" % nf.dump())
      # Discover and add NF connections
      for u, v, l in nffg.real_out_edges_iter(nf.id):
        if l.type != NFFG.TYPE_LINK_DYNAMIC:
          continue
        # Explicitly add links for both direction
        link1, link2 = sbb.add_undirected_link(port1=c_nf.ports[l.src.id],
                                               port2=sbb_infra.add_port(
                                                 id=l.dst.id),
                                               p1p2id=l.id,
                                               p2p1id="%s-back" % l.id,
                                               dynamic=True,
                                               delay=l.delay,
                                               bandwidth=l.bandwidth)
        log.debug("Added connection: %s" % link1)
        log.debug("Added connection: %s" % link2)
    # Use SAP id --> SBB port id cache for delay matrix calculation
    delay_matrix_cache = {}
    # Add existing SAPs and their connections to the SingleBiSBiS infra
    for sap in nffg.saps:
      c_sap = sbb.add_sap(sap_obj=sap.copy())
      log.debug("Added SAP: %s" % c_sap)
      log.log(5, "SAP:\n%s" % c_sap.dump())
      # Discover and add SAP connections
      for u, v, l in nffg.real_out_edges_iter(sap.id):
        if len(sap.ports) > 1:
          log.warning("SAP contains multiple port!")
        sbb_infra_port = sbb_infra.add_port(id=str(c_sap.id),
                                            sap=sap.ports.container[0].sap)
        # Explicitly add links for both direction
        link1, link2 = sbb.add_undirected_link(port1=c_sap.ports[l.src.id],
                                               port2=sbb_infra_port,
                                               p1p2id=l.id,
                                               p2p1id="%s-back" % l.id,
                                               delay=l.delay,
                                               bandwidth=l.bandwidth)
        log.debug("Added connection: %s" % link1)
        log.debug("Added connection: %s" % link2)
        delay_matrix_cache[c_sap.id] = sbb_infra_port.id
    # Shortest paths in format of dict in dict keyed with node ids
    # e.g. SAP2 --> EE1 --> 4.9
    latency_paths = NFFGToolBox.shortestPathsInLatency(G=nffg.network)
    log.log(5, "Calculated latency paths for delay matrix:\n%s"
            % pprint.pformat(latency_paths))
    log.log(5, "Collected SAP ports for delay matrix:\n%s"
            % pprint.pformat(delay_matrix_cache))
    dm_elements = itertools.permutations(delay_matrix_cache.keys(), 2)
    for src, dst in dm_elements:
      if src not in latency_paths:
        log.warning("Missing node: %s for latency paths: %s!"
                    % (src, (src, dst)))
        continue
      if dst not in latency_paths[src]:
        log.warning("Missing node: %s for latency paths: %s!"
                    % (src, (src, dst)))
      else:
        sbb_infra.delay_matrix.add_delay(src=src,
                                         dst=dst,
                                         delay=latency_paths[src][dst])
        log.debug("Added delay matrix element [%s --> %s]: %s"
                  % (src, dst, latency_paths[src][dst]))
    # Recreate flowrules based on NBalazs functions
    sg_hop_info = NFFGToolBox.get_all_sghop_info(nffg=nffg)
    log.debug("Detected SG hop info:\n%s" % pprint.pformat(sg_hop_info))
    log.debug("Recreate flowrules...")
    for sg_id, value in sg_hop_info.iteritems():
      sg_src_node = value[0].node.id
      sg_src_port = value[0].id
      sg_dst_node = value[1].node.id
      sg_dst_port = value[1].id
      flowclass = value[2]
      fr_bw = value[3]
      fr_delay = value[4]
      fr_hop = sg_id
      sbb_src_port = [l.dst for u, v, l in
                      sbb.network.out_edges_iter(sg_src_node, data=True) if
                      l.src.id == sg_src_port and l.src.node.id == sg_src_node]
      if len(sbb_src_port) < 1:
        log.warning("No opposite Port(node: %s, id: %s) was found for SG hop: "
                    "%s in new SingleBiSBiS node" % (
                      sg_src_node, sg_src_port, fr_hop))
        continue
      if len(sbb_src_port) > 1:
        log.warning("Too much Port(node: %s, id: %s) was found for SG hop: "
                    "%s in new SingleBiSBiS node: %s" % (
                      sg_src_node, sg_src_port, fr_hop, sbb_src_port))
        continue
      sbb_src_port = sbb_src_port.pop()
      sbb_dst_port = [l.dst for u, v, l in
                      sbb.network.out_edges_iter(sg_dst_node, data=True) if
                      l.src.id == sg_dst_port and l.src.node.id == sg_dst_node]
      if len(sbb_dst_port) < 1:
        log.warning("No opposite Port(node: %s, id: %s) was found for SG hop: "
                    "%s in new SingleBiSBiS node" % (
                      sg_dst_node, sg_dst_port, fr_hop))
        continue
      if len(sbb_dst_port) > 1:
        log.warning("Too much Port(node: %s, id: %s) was found for SG hop: "
                    "%s in new SingleBiSBiS node: %s" % (
                      sg_dst_node, sg_dst_port, fr_hop, sbb_dst_port))
        continue
      sbb_dst_port = sbb_dst_port.pop()
      if flowclass:
        fr_match = "in_port=%s;flowclass=%s" % (sbb_src_port.id, flowclass)
      else:
        fr_match = "in_port=%s" % sbb_src_port.id
      fr_action = "output=%s" % sbb_dst_port.id
      if value[0].node.type == NFFG.TYPE_SAP and \
            value[1].node.type == NFFG.TYPE_NF and \
            value[0].sap is not None:
        # Update action for flowrule connecting inter-domain SAP to NF
        fr_action += ";UNTAG"
      fr = sbb_src_port.add_flowrule(id=fr_hop,
                                     match=fr_match,
                                     action=fr_action,
                                     bandwidth=fr_bw,
                                     delay=fr_delay, )
      log.debug("Added flowrule: %s" % fr)
    if add_sg_hops:
      log.debug("Recreate SG hops...")
      for sg_id, value in sg_hop_info.iteritems():
        sg_src_port = value[0]
        sg_dst_port = value[1]
        hop_fc = value[2]
        hop_bw = value[3]
        hop_delay = value[4]
        sg = sbb.add_sglink(id=sg_id,
                            src_port=sg_src_port,
                            dst_port=sg_dst_port,
                            flowclass=hop_fc,
                            delay=hop_delay,
                            bandwidth=hop_bw)
        log.debug("Added SG hop: %s" % sg)
    else:
      log.debug("Skip SG hop recreation for the SingleBiSBiS!")
    NFFGToolBox.rewrite_interdomain_tags([(sbb.id, sbb)])
    log.debug("END SBB generation...")
    # Return with Single BiSBiS infra
    return sbb

  ##############################################################################
  # ----------------------- Domain update functions -----------------------
  ##############################################################################

  @classmethod
  def clear_domain (cls, base, domain, log=logging.getLogger("CLEAN")):
    """
    Clean domain by removing initiated NFs and flowrules related to BiSBiS
    nodes of the given domain

    :param base: base NFFG object
    :type base: :class:`NFFG`
    :param domain: domain name
    :type domain: str
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    base_domain = cls.detect_domains(nffg=base)
    if domain not in base_domain:
      log.warning("No node was found in %s with domain: %s for cleanup! "
                  "Leave NFFG unchanged..." % (base, domain))
      return base
    for infra in base.infras:
      deletable_ports = set()
      deletable_nfs = set()
      # Skip nodes from other domains
      if infra.domain != domain:
        continue
      # Iterate over out edges from the current BB node
      for infra_id, node_id, link in base.real_out_edges_iter(infra.id):
        # Mark connected NF for deletion
        if base[node_id].type in (NFFG.TYPE_NF,):
          deletable_nfs.add(node_id)
          # Mark related dynamic port for deletion
          deletable_ports.add(link.src)
      if deletable_nfs:
        log.debug("Initiated NFs marked for deletion: %s on node: %s" %
                  (deletable_nfs, infra.id))
      # Remove NFs
      base.network.remove_nodes_from(deletable_nfs)
      if deletable_ports:
        log.debug("Dynamic ports marked for deletion: %s on node: %s" %
                  (deletable_ports, infra.id))
      # Remove dynamic ports
      for p in deletable_ports:
        base[infra.id].ports.remove(p)
      # Delete flowrules from ports
      for port in base[infra.id].ports:
        port.clear_flowrules()
    return base

  @classmethod
  def remove_domain (cls, base, domain, log=logging.getLogger("REMOVE")):
    """
    Remove elements from the given ``base`` :class:`NFFG` with given ``domain``
    name.

    :param base: base NFFG object
    :type base: :class:`NFFG`
    :param domain: domain name
    :type domain: str
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    log.debug("Remove nodes and edges which part of the domain: %s from %s..."
              % (domain, base))
    # Check existing domains
    base_domain = cls.detect_domains(nffg=base)
    if domain not in base_domain:
      log.warning("No node was found in %s with domain: %s for removing! "
                  "Leave NFFG unchanged..." % (base, domain))
      return base
    deletable = set()
    for infra in base.infras:
      # Add deletable infras
      if infra.domain != domain:
        continue
      deletable.add(infra.id)
      # Add deletable SAP/NF connected to iterated infra
      for node_id in base.real_neighbors_iter(infra.id):
        if base[node_id].type in (NFFG.TYPE_SAP, NFFG.TYPE_NF):
          deletable.add(node_id)
    log.debug("Nodes marked for deletion: %s" % deletable)
    base.network.remove_nodes_from(deletable)
    if len(base):
      log.debug("Remained nodes after deletion: %s" % [n for n in base])
    else:
      log.debug("No node was remained after splitting! ")
    log.debug("Search for inter-domain SAP ports and "
              "recreate associated SAPs...")
    cls.recreate_inter_domain_SAPs(nffg=base, log=log)
    # Check orphaned or not connected nodes and remove them
    log.debug("Trim orphaned nodes from updated NFFG...")
    cls.trim_orphaned_nodes(nffg=base, log=log)
    return base

  @classmethod
  def update_domain (cls, base, updated, log):
    """
    Update the given ``updated`` nffg into the ``base`` NFFG.

    :param base: base NFFG object
    :type base: :class:`NFFG`
    :param updated: updated domain information
    :type updated: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    # Get new domain name
    domain = cls.detect_domains(nffg=updated)
    if len(domain) == 0:
      log.error("No domain detected in new %s!" % updated)
      return
    if len(domain) > 1:
      log.warning("Multiple domain name detected in new %s!" % updated)
      return
    domain = domain.pop()
    log.debug("Update elements of domain: %s in %s..." % (domain, base.id))
    base_infras = {i.id for i in base.infras if i.domain == domain}
    if len(base_infras) == 0:
      log.warning("No Node was found in the base %s! Use merging..." % base)
      return cls.merge_new_domain(base=base, nffg=updated, log=log)
    # If infra nodes were removed or added, best way is to remerge domain
    else:
      # TODO - implement real update
      log.error("Domain update has not implemented yet!")

  ##############################################################################
  # ------------------- Status info-based update functions ---------------------
  ##############################################################################

  @classmethod
  def update_status_info (cls, nffg, status,
                          log=logging.getLogger("UPDATE-STATUS")):
    """
    Update the mapped elements of given nffg with given status.

    :param nffg: base NFFG object
    :type nffg: :class:`NFFG`
    :param status: new status
    :type status: str
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    log.debug("Add %s status for NFs and Flowrules..." % status)
    for nf in nffg.nfs:
      nf.status = status
    for infra in nffg.infras:
      for flowrule in infra.flowrules():
        flowrule.status = status
    return nffg

  @classmethod
  def update_nffg_by_status (cls, base, updated,
                             log=logging.getLogger("UPDATE-DOMAIN-STATUS")):
    """
    Update status of the elements of the given ``base`` nffg  based on the
    given ``updated`` nffg.

    :param base: base NFFG object
    :type base: :class:`NFFG`
    :param updated: updated domain information
    :type updated: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    # Update NF status
    base_nfs = {nf.id for nf in base.nfs}
    updated_nfs = {nf.id for nf in updated.nfs}
    log.debug("Update status of NF nodes: %s" % updated_nfs)
    for nf in base_nfs:
      if nf in updated_nfs:
        base[nf].status = updated[nf].status
      else:
        log.warning("Missing NF: %s from base NFFG: %s" % (nf, base))
    # Update Flowrule status
    base_infras = {infra.id for infra in base.infras}
    updated_infras = {infra.id for infra in updated.infras}
    log.debug("Update status of flowrules in Infra nodes: %s" % updated_infras)
    for infra_id in base_infras:
      # Skip Infras from other domains
      if infra_id not in updated_infras:
        continue
      for port in base[infra_id].ports:
        if port.id not in updated[infra_id].ports:
          log.warning("Port: %s in Infra: %s is not in the updated NFFG! "
                      "Skip flowrule status update in this Port..."
                      % (port.id, infra_id))
          continue
        # updated_frs = {f.id for f in
        #                updated[infra_id].ports[port.id].flowrules}
        # for fr in base[infra_id].ports[port.id].flowrules:
        #   if fr.id not in updated_frs:
        #     log.warning("Flowrule: %s is not in the updated NFFG! "
        #                 "Skip flowrule status update..." % fr)
        #     continue
        #   for f in updated[infra_id].ports[port.id].flowrules:
        #     if f.id == fr.id:
        #       fr.status = f.status
        for fr in base[infra_id].ports[port.id].flowrules:
          changed = False
          for ufr in updated[infra_id].ports[port.id].flowrules:
            # Theoretically in a port there is only one flowrule with a given
            #  hop_id --> if the hop_ids are the same it must be the same fr
            if fr.id == ufr.id:
              fr.status = ufr.status
              changed = True
              break
          if not changed:
            log.warning("Flowrule: %s is not in the updated NFFG! "
                        "Skip flowrule status update..." % fr)
    return base

  @classmethod
  def update_status_by_dov (cls, nffg, dov, init_status=NFFG.STATUS_PENDING,
                            log=logging.getLogger("UPDATE-DOV-STATUS")):
    """
    Update status of the elements of the given ``base`` nffg  based on the
    given ``updated`` nffg.

    :param nffg: base NFFG object
    :type nffg: :class:`NFFG`
    :param dov: updated domain information
    :type dov: :class:`NFFG`
    :type init_status: init status of new element
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the update base NFFG
    :rtype: :class:`NFFG`
    """
    # Update NF status
    nffg_nfs = {nf.id for nf in nffg.nfs}
    dov_nfs = {nf.id for nf in dov.nfs}
    log.debug("Update status of existing NF nodes: %s" % nffg_nfs)
    for nf in nffg_nfs:
      if nf in dov_nfs:
        nffg[nf].status = dov[nf].status
      else:
        nffg[nf].status = init_status
    # Update Flowrule status
    for infra in nffg.infras:
      for flowrule in infra.flowrules():
        flowrule.status = init_status
    nffg_infras = {infra.id for infra in nffg.infras}
    dov_infras = {infra.id for infra in dov.infras}
    log.debug("Update status of existing flowrules in Infra nodes: %s" %
              nffg_infras)
    for infra_id in nffg_infras:
      if infra_id not in dov_infras:
        continue
      for port in nffg[infra_id].ports:
        if port.id not in dov[infra_id].ports:
          continue
        dov_frs = {f.id for f in dov[infra_id].ports[port.id].flowrules}
        for fr in nffg[infra_id].ports[port.id].flowrules:
          if fr.id not in dov_frs:
            fr.status = init_status
          for f in dov[infra_id].ports[port.id].flowrules:
            if f.id == fr.id:
              fr.status = f.status
    return nffg

  def filter_non_running_NFs (self, nffg, log=logging.getLogger("FILTER")):
    """
    Create a new NFFG from the given ``nffg`` and filter out the
    stopped/failed Nfs.

    :param nffg: base NFFG object
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: None
    """
    # TODO implement
    pass

  @classmethod
  def remove_deployed_services (cls, nffg, log=logging.getLogger("CLEAN")):
    """
    Remove all the installed NFs, flowrules and dynamic ports from given NFFG.

    :param nffg: base NFFG
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: the cleaned nffg
    :rtype: :class:`NFFG`
    """
    for infra in nffg.infras:
      log.debug("Remove deployed elements from Infra: %s" % infra.id)
      del_ports = []
      del_nfs = []
      for src, dst, link in nffg.network.out_edges_iter(data=True):
        if link.type == NFFG.TYPE_LINK_DYNAMIC and \
              link.dst.node.type == NFFG.TYPE_NF:
          del_nfs.append(dst)
          del_ports.append(link.src.id)
      if del_nfs:
        nffg.network.remove_nodes_from(del_nfs)
        log.debug("Removed NFs: %s" % del_nfs)
      if del_ports:
        for id in del_ports:
          infra.del_port(id)
        log.debug("Removed dynamic ports: %s" % del_ports)
      log.debug("Clear flowrules...")
      for port in infra.ports:
        port.clear_flowrules()

    return nffg

  ##############################################################################
  # ----------------------- High level NFFG operations ------------------------
  ##############################################################################

  @classmethod
  def _copy_node_type (cls, type_iter, target, log):
    """
    Copies all element from iterator if it is not in target, and merges their
    port lists.

    :param type_iter: Iterator on objects to be added
    :type type_iter: :any: iterator on `Node`
    :param target: The target NFFG
    :type target: :any: `NFFG`
    :return: the updated base NFFG
    :rtype: :class:`NFFG`
    """
    for obj in type_iter:
      if obj.id not in target:
        c_obj = target.add_node(deepcopy(obj))
        log.debug("Copy NFFG node: %s" % c_obj)
      else:
        for p in obj.ports:
          if p.id not in target.network.node[obj.id].ports:
            target.network.node[obj.id].add_port(id=p.id,
                                                 properties=p.properties)
            # TODO: Flowrules are not copied!
            log.debug("Copy port %s to NFFG element %s" % (p, obj))
    return target

  @classmethod
  def _copy_node_type_with_flowrules (cls, type_iter, target, log):
    """
    Copies all element from iterator if it is not in target, and merges their
    port lists.

    :param type_iter: Iterator on objects to be added
    :type type_iter: :any: iterator on `Node`
    :param target: The target NFFG
    :type target: :any: `NFFG`
    :return: the updated base NFFG
    :rtype: :class:`NFFG`
    """
    for obj in type_iter:
      if obj.id not in target:
        c_obj = target.add_node(deepcopy(obj))
        log.debug("Copy NFFG node: %s" % c_obj)
      else:
        for p in obj.ports:
          if p.id not in target.network.node[obj.id].ports:
            new_port = target.network.node[obj.id].add_port(id=p.id,
                                                            properties=p.properties)
            log.debug("Copy port %s to NFFG element %s" % (p, obj))
            if hasattr(p, 'flowrules'):
              log.debug("Merging flowrules of port %s of node %s" %
                        (p.id, obj.id))
              for fr in p.flowrules:
                if fr.id not in (f.id for f in new_port.flowrules):
                  new_port.flowrules.append(copy.deepcopy(fr))
          else:
            old_port = target.network.node[obj.id].ports[p.id]
            for fr in p.flowrules:
              if fr.id not in (f.id for f in old_port.flowrules):
                old_port.flowrules.append(copy.deepcopy(fr))
    return target

  @classmethod
  def merge_nffgs (cls, target, new, log=logging.getLogger("UNION")):
    """
    Merges new `NFFG` to target `NFFG` keeping all parameters and copying
    port object from new. Comparison is done based on object id, resources and
    requirements are kept unchanged in target.

    :param target: target NFFG object
    :type target: :class:`NFFG`
    :param new: NFFG object to merge from
    :type new: :class:`NFFG`
    :return: the updated base NFFG
    :rtype: :class:`NFFG`
    """
    # Copy Infras
    target = cls._copy_node_type_with_flowrules(new.infras, target, log)
    # Copy NFs
    target = cls._copy_node_type(new.nfs, target, log)
    # Copy SAPs
    target = cls._copy_node_type(new.saps, target, log)

    # Copy remaining links which should be valid
    for u, v, link in new.network.edges_iter(data=True):
      if not target.network.has_edge(u, v, key=link.id):
        src_port = target.network.node[u].ports[link.src.id]
        dst_port = target.network.node[v].ports[link.dst.id]
        c_link = deepcopy(link)
        c_link.src = src_port
        c_link.dst = dst_port
        target.add_link(src_port=src_port, dst_port=dst_port, link=c_link)
        log.debug("Copy Link: %s" % c_link)
    return target

  @classmethod
  def subtract_nffg (cls, minuend, subtrahend, consider_vnf_status=False,
                     ignore_infras=False):
    """
    Deletes every (all types of) node from minuend which have higher degree in
    subtrahend. And removes every (all types of) edge from minuend which are
    present in subtrahend. Changes minuend, but doesn't change subtrahend.
    NOTE: a node cannot be decreased to degree 0, because then it will be
    removed.

    :param minuend: minuend NFFG object
    :type minuend: :class:`NFFG`
    :param subtrahend: NFFG object to be subtracted
    :type subtrahend: :class:`NFFG`
    :return: NFFG which is minuend \ subtrahend
    :rtype: :class:`NFFG`
    """
    if ignore_infras:
      minuend_degrees = {}
      for nf in minuend.nfs:
        minuend_degrees[nf.id] = len(minuend.adjacent_sghops(nf.id))
      subtrahend_degrees = [(nf.id, len(subtrahend.adjacent_sghops(nf.id))) \
                            for nf in subtrahend.nfs]
    else:
      minuend_degrees = minuend.network.degree()
      subtrahend_degrees = subtrahend.network.degree().iteritems()
    for n, d in subtrahend_degrees:
      if n in minuend_degrees:
        if d >= minuend_degrees[n]:
          # If their status shall be considered AND the statuses are equal then
          # they are considered equal and it shouldn't be in the minuend.
          if not consider_vnf_status or (consider_vnf_status and
                                             subtrahend.network.node[
                                               n].status ==
                                             minuend.network.node[n].status):
            for edge_func in (minuend.network.in_edges_iter,
                              minuend.network.out_edges_iter):
              for i, j, d in edge_func([n], data=True):
                if d.type == 'SG':
                  minuend.del_flowrules_of_SGHop(d.id)
            minuend.del_node(minuend.network.node[n])
    for i, j, k, d in subtrahend.network.edges_iter(keys=True, data=True):
      if minuend.network.has_edge(i, j, key=k):
        minuend.del_edge(i, j, k)
        if d.type == 'SG':
          minuend.del_flowrules_of_SGHop(d.id)
    return minuend

  @classmethod
  def generate_difference_of_nffgs (cls, old, new, ignore_infras=False):
    """
    Creates two NFFG objects which can be used in NFFG.MODE_ADD and
    NFFG.MODE_DEL
    operation modes of the mapping algorithm. Doesn't modify input objects.
    If infra nodes shall be ignored, node degree comparison is only based on 
    SGHops, but the output structure still contains the infras which were in 
    the input.

    :param old: old NFFG object
    :type old: :class:`NFFG`
    :param new: NFFG object of the new config
    :type new: :class:`NFFG`
    :return: a tuple of NFFG-s for addition and deletion resp. on old config.
    :rtype: tuple
    """
    add_nffg = copy.deepcopy(new)
    add_nffg.mode = NFFG.MODE_ADD
    del_nffg = copy.deepcopy(old)
    del_nffg.mode = NFFG.MODE_DEL
    add_nffg = NFFGToolBox.subtract_nffg(add_nffg, old,
                                         consider_vnf_status=True,
                                         ignore_infras=ignore_infras)
    del_nffg = NFFGToolBox.subtract_nffg(del_nffg, new,
                                         ignore_infras=ignore_infras)
    # WARNING: we always remove the EdgeReqs from the delete NFFG, this doesn't
    # have a defined meaning so far.
    for req in [r for r in del_nffg.reqs]:
      del_nffg.del_edge(req.src, req.dst, req.id)

    # NOTE: It should be possible to delete an NF, which is not connected
    # anywhere. With setting and using the operation field of NFs, NFs with
    # no connected SGhops are possible.
    # for n, d in [t for t in del_nffg.network.nodes(data=True)]:
    #   if del_nffg.network.out_degree(n) + del_nffg.network.in_degree(n) == 0:
    #     del_nffg.del_node(d)
    # NOTE: set operation delete to filter removing NFs which wouldn't have
    # left any more connected SGHops.
    for del_nf in del_nffg.nfs:
      if del_nf.id in old.network.nodes_iter() and \
            del_nf.id not in new.network.nodes_iter():
        del_nf.operation = NFFG.OP_DELETE

    # The output ADD NFFG shall still include the Infras even if they were
    # ignored during the difference calculation.

    # Copy data from new NFFG to old NFFG
    add_nffg.id = del_nffg.id = new.id
    add_nffg.name = del_nffg.name = new.name
    add_nffg.metadata = new.metadata.copy()
    del_nffg.metadata = new.metadata.copy()

    return add_nffg, del_nffg

  ##############################################################################
  # --------------------- Mapping-related NFFG operations ----------------------
  ##############################################################################

  @staticmethod
  def _find_infra_link (nffg, port, outbound=True, accept_dyn=False):
    """
    Returns the object of a static link which is connected to 'port'.
    If None is returned, we can suppose that the port is dynamic.

    :param nffg: NFFG object which contains port.
    :type nffg: :class:`NFFG`
    :param port: The port which should be the source or destination.
    :type port: :any:`Port`
    :param outbound: Determines whether outbound or inbound link should be found
    :type outbound: bool
    :param accept_dyn: accepts DYNAMIC links too
    :type outbound: bool
    :return: found static link or None
    :rtype: :any:`Link`
    """
    edges_func = None
    link = None
    if outbound:
      edges_func = nffg.network.out_edges_iter
    else:
      edges_func = nffg.network.in_edges_iter
    for i, j, d in edges_func([port.node.id], data=True):
      if d.type == 'STATIC' or (accept_dyn and d.type == 'DYNAMIC'):
        if outbound and port.id == d.src.id:
          if link is not None:
            raise RuntimeError("InfraPort %s has more than one outbound "
                               "links!" % port.id)
          link = d
        if not outbound and port.id == d.dst.id:
          if link is not None:
            raise RuntimeError("InfraPort %s has more than one inbound "
                               "links!" % port.id)
          link = d
    if link == None:
      raise RuntimeError(" ".join(("Dynamic" if accept_dyn else "Static",
                                   "outbound" if outbound else "inbound",
                                   "link couldnt be found connected to port",
                                   str(port))))
    return link

  @staticmethod
  def try_to_convert (id):
    """
    Tries to convert a string type ID to integer (base 10).

    :param id: ID to be converted
    :type id: str
    :return: integer ID if it can be converted, string otherwise
    :rtype: int
    """
    converted = id
    try:
      converted = int(id)
    except ValueError:
      pass
    return converted

  @staticmethod
  def _extract_flowclass (splitted_matches):
    """
    Interprets the match field of a flowrule as everything is flowclass except
    "TAG=" and "in_port=" fields. Returns the string to be put into the
    flowclass field. Hopefully the order of the match segments are kept or
    irrelevant.

    :param splitted_matches: elements of the match field
    :type splitted_matches: list
    :return: flowclass value
    :rtype: str
    """
    flowclass = ""
    for match in splitted_matches:
      field, mparam = match.split("=", 1)
      if field == "flowclass":
        flowclass += mparam
      elif field != "TAG" and field != "in_port":
        flowclass += "".join((field, "=", mparam))
    if flowclass == "":
      return None
    else:
      return flowclass

  @staticmethod
  def _get_flowrule_and_its_starting_port (infra, fr_id):
    """
    Finds the Flowrule which belongs to the path of SGHop with ID 'fr_id'.

    :param infra: Infra object where we should look for the Flowrule
    :type infra: :any:`NodeInfra`
    :param fr_id: Flowrule/SGHop ID to look for
    :type fr_id: int
    :return: Flowrule and its containing InfraPort
    :rtype: 2-tuple
    """
    for p in infra.ports:
      for fr in p.flowrules:
        if fr.id == fr_id:
          return fr, p
    else:
      raise RuntimeError("Couldn't find Flowrule for SGHop %s in Infra %s!"
                         % (fr_id, infra.id))

  @staticmethod
  def _get_output_port_of_flowrule (infra, fr):
    """
    Find the port object where this Flowrule sends the traffic out.

    :param infra: Infra object where we should look for the InfraPort.
    :type infra: :any:`NodeInfra`
    :return: The output infra port.
    :rtype: :any:`InfraPort`
    """
    for action in fr.action.split(";"):
      comm, arg = action.split("=", 1)
      if comm == 'output':
        if "://" in arg:
          # target-less flow rule -> skip
          return
        arg = NFFGToolBox.try_to_convert(arg)
        return infra.ports[arg]
    else:
      raise RuntimeError("Couldn't find output InfraPort object for Flowrule %s"
                         " in Infra%s!" % (fr.id, infra.id))

  @staticmethod
  def _check_flow_consistencity (sg_map, fr_sg):
    """
    Checks whether there is an inconsistencity with Flowrule or SGHop 'fr_sg'
    and the other flowrules which are part of the SGHop's sequence OR SGHop
    which is in sg_map. Throws runtime exception if error found.
    Uses only the common fields of Flowrules and SGHops.
    'flowclass' needs to be extracted if 'fr_sg' is not an SGHop.
    """
    if isinstance(fr_sg, Flowrule):
      flowclass = NFFGToolBox._extract_flowclass(fr_sg.match.split(";"))
    else:
      flowclass = fr_sg.flowclass
    consistent = True
    if sg_map[fr_sg.id][2] != flowclass:
      consistent = False
    if (sg_map[fr_sg.id][3] is None or sg_map[fr_sg.id][3] == float("inf")) != \
       (fr_sg.bandwidth is None or fr_sg.bandwidth == float("inf")):
      # If not both of them are None
      consistent = False
    elif (sg_map[fr_sg.id][3] is not None) and (fr_sg.bandwidth is not None):
      if consistent and math.fabs(sg_map[fr_sg.id][3] - fr_sg.bandwidth) > 1e-8:
        consistent = False
    if (sg_map[fr_sg.id][4] is None or sg_map[fr_sg.id][4] == 0.000000000) != \
       (fr_sg.delay is None or fr_sg.delay == 0.0000000000):
      # If not both of them are None
      consistent = False
    elif (sg_map[fr_sg.id][4] is not None) and (fr_sg.delay is not None):
      if math.fabs(sg_map[fr_sg.id][4] - fr_sg.delay) > 1e-8:
        consistent = False
    if not consistent:
      raise RuntimeError("Not all data of a Flowrule equal to the other "
                         "Flowrules of the sequence for the SGHop %s! Or the"
                         " SGHop to be added differs in data from the existing"
                         " SGHop!" % fr_sg.id)

  @staticmethod
  def get_all_sghop_info (nffg, return_paths=False):
    """
    Returns a dictionary keyed by sghopid, data is [PortObjsrc,
    PortObjdst, SGHop.flowclass, SGHop.bandwidth, SGHop.delay] list of port
    objects. Source and destination VNF-s can be retreived from port references
    (port.node.id). The function 'recreate_all_sghops' should receive this exact
    NFFG object and the output of this function.
    It is based exclusively on flowrules, flowrule ID-s are equal to the
    corresponding SGHop's ID.
    If return_paths is set, the 6th element in the dict values is always an
    unordered list of the STATIC link references, which are used by the flowrule
    sequence. Doesn't change the input NFFG, only returns the SGHop values,
    SGHops are not added.

    :param nffg: the processed NFFG object
    :type nffg: :class:`NFFG`
    :param return_paths: flag for returning paths
    :type returning: bool
    :return: extracted values
    :rtype: dict
    """
    sg_map = {}
    for i in nffg.infras:
      for p in i.ports:
        for fr in p.flowrules:
          # if fr.external:
          #   continue
          if fr.id not in sg_map:
            # The path is unordered!!
            path_of_shop = []
            flowclass = NFFGToolBox._extract_flowclass(fr.match.split(";"))
            sg_map[fr.id] = [None, None, flowclass, fr.bandwidth, fr.delay]
            # We have to find the BEGINNING of this flowrule sequence.
            inbound_link = NFFGToolBox._find_infra_link(nffg, p, outbound=False,
                                                        accept_dyn=True)
            while inbound_link.type != 'DYNAMIC':
              path_of_shop.append(inbound_link)
              if inbound_link.src.node.type == 'SAP':
                break
              # The link is STATIC, and its src is not SAP so it is an Infra.
              prev_fr, prev_p = \
                NFFGToolBox._get_flowrule_and_its_starting_port(
                  inbound_link.src.node, fr.id)
              NFFGToolBox._check_flow_consistencity(sg_map, prev_fr)
              inbound_link = NFFGToolBox._find_infra_link(nffg, prev_p,
                                                          outbound=False,
                                                          accept_dyn=True)
            # 'inbound_link' is DYNAMIC here or it is STATIC and starts from
            # a SAP,
            # so the sequence starts here
            sg_map[fr.id][0] = inbound_link.src

            # We have to find the ENDING of this flowrule sequence.
            output_port = NFFGToolBox._get_output_port_of_flowrule(i, fr)
            if output_port is None:
              continue
            outbound_link = NFFGToolBox._find_infra_link(nffg, output_port,
                                                         outbound=True,
                                                         accept_dyn=True)
            while outbound_link.type != 'DYNAMIC':
              path_of_shop.append(outbound_link)
              if outbound_link.dst.node.type == 'SAP':
                break
              # The link is STATIC and its dst is not a SAP so it is an Infra.
              next_fr, _ = NFFGToolBox._get_flowrule_and_its_starting_port(
                outbound_link.dst.node, fr.id)
              # '_' is 'outbound_link.dst'
              next_output_port = NFFGToolBox._get_output_port_of_flowrule(
                outbound_link.dst.node, next_fr)
              NFFGToolBox._check_flow_consistencity(sg_map, next_fr)
              outbound_link = NFFGToolBox._find_infra_link(nffg,
                                                           next_output_port,
                                                           outbound=True,
                                                           accept_dyn=True)
            # the 'outbound_link' is DYNAMIC here or finishes in a SAP, so the
            # flowrule sequence finished here.
            sg_map[fr.id][1] = outbound_link.dst

            if return_paths:
              sg_map[fr.id].append(path_of_shop)

    return sg_map

  @staticmethod
  def recreate_all_sghops (nffg):
    """
    Extracts the SGHop information from the input NFFG, and creates the SGHop
    objects in the NFFG.

    :param nffg: the NFFG to look for SGHop info and to modify
    :type nffg: :class:`NFFG`
    :return: the modified NFFG
    :rtype: :class:`NFFG`
    """
    sg_map = NFFGToolBox.get_all_sghop_info(nffg)
    for sg_hop_id, data in sg_map.iteritems():
      src, dst, flowclass, bandwidth, delay = data
      if not (src and dst):
        continue
      if not nffg.network.has_edge(src.node.id, dst.node.id, key=sg_hop_id):
        nffg.add_sglink(src, dst, id=sg_hop_id, flowclass=flowclass,
                        bandwidth=bandwidth, delay=delay)
        # causes unnecesary failures, when bandwidth or delay is missing
        # somewhere
        # else:
        #    sg_hop = nffg.network[src.node.id][dst.node.id][sg_hop_id]
        #    NFFGToolBox._check_flow_consistencity(sg_map, sg_hop)
    return nffg

  @staticmethod
  def redirect_flowrules (from_port, to_port, infra, mark_external=False,
                          log=logging.getLogger("MOVE")):
    """
    Redirect flowrules from `from` to `to_port` handling match/action fields.

    :param from_port: origin port
    :type from_port: :class:`InfraPort`
    :param to_port: target port
    :type to_port: :class:`InfraPort`
    :param infra: container node
    :type infra: :class:`NodeInfra`
    :param mark_external: mark redirected flowrule as external
    :type mark_external: bool
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: None
    """
    # Flowrules pointing to the from_port -> rewrite output reference in action
    for port in infra.ports:
      for fr in port.flowrules:
        output = fr.action.split(';', 1)[0].split('=', 1)[1]
        try:
          output = int(output)
        except ValueError:
          pass
        if output == from_port.id:
          # Rewrite output tag
          fr.action = fr.action.replace("output=%s" % output,
                                        "output=%s" % to_port.id, 1)
          if mark_external:
            fr.external = True
          log.debug("Rewritten inbound flowrule: %s" % fr)
    # Contained flowrules need to be rewritten and moved to the target port
    for fr in from_port.flowrules:
      # Rewrite in_port tag
      fr.match = fr.match.replace(fr.match.split(';', 1)[0],
                                  "in_port=%s" % to_port.id, 1)
      if mark_external:
        fr.external = True
      # Move flowrule
      to_port.flowrules.append(fr)
      log.debug("Moved outbound flowrule: %s" % fr)
    # Clear flowrule list
    del from_port.flowrules[:]

  @classmethod
  def merge_external_ports (cls, nffg, log=logging.getLogger("MERGE")):
    """
    Merge detected external ports in nodes of given `nffg` 
    and only leave the original SAP port.
    
    :param nffg: container node
    :type nffg: :class:`NFFG`
    :param log: additional logger
    :type log: :any:`logging.Logger`
    :return: None
    """
    for infra in nffg.infras:
      for ext_port in [p for p in infra.ports if p.role == "EXTERNAL"]:
        log.debug("Found external port: %s" % ext_port)
        # Collect ports with the same SAP tag
        origin_port = [p for p in infra.ports if p.sap == ext_port.sap and
                       p.role != "EXTERNAL"]
        if len(origin_port) != 1:
          log.error("Original port for external port: %s is not found uniquely:"
                    " %s" % (ext_port, origin_port))
          continue
        origin_port = origin_port.pop()
        log.debug("Detected original port for %s -> %s" % (ext_port.id,
                                                           origin_port))
        # Move flowrules
        log.debug("Redirect external port %s traffic into %s..."
                  % (ext_port, origin_port))
        cls.redirect_flowrules(from_port=ext_port, to_port=origin_port,
                               infra=infra, mark_external=True, log=log)
        # Remove external port
        log.debug("Remove external SAP: %s" % ext_port.id)
        nffg.del_node(node=nffg[ext_port.id])
        infra.ports.remove(ext_port)

  @classmethod
  def isStaticInfraPort (cls, G, p):
    """
    Return true if there is a Static outbound or inbound EdgeLink, false if 
    there
    is a Dynamic outbound or inbound link, throws exception if borth, or warning
    if multiple of the same type.
    :param G:
    :param p:
    :return:
    """
    static_link_found = False
    dynamic_link_found = False
    for edge_func, src_or_dst in ((G.out_edges_iter, 'src'),
                                  (G.in_edges_iter, 'dst')):
      for i, j, k, link in edge_func([p.node.id], data=True, keys=True):
        src_or_dst_port = getattr(link, src_or_dst)
        # check if we have found the right port
        if src_or_dst_port.id == p.id:
          if link.type == NFFG.TYPE_LINK_DYNAMIC:
            dynamic_link_found = True
          elif link.type == NFFG.TYPE_LINK_STATIC:
            static_link_found = True
    if dynamic_link_found and static_link_found:
      raise RuntimeError(
        "An InfraPort should either be connected to STATIC or DYNAMIC links "
        "Both STATIC and DYNAMIC in/outbound links found to port %s of Infra "
        "%s" % (p.id, p.node.id))
    elif not dynamic_link_found and not static_link_found:
      # If a port is found which is not connected to any STATIC or DYNAMIC link
      return False
    elif static_link_found:
      return True
    elif dynamic_link_found:
      return False

  @classmethod
  def explodeGraphWithPortnodes (cls, G, id_connector_character):
    """
    Makes ports of the original graph into the nodes of a new NetworkX graph,
    adds delay values onto edge data. The returned graph can be used by standard
    networkx algorithms.
    :param id_connector_character: character which is used to concatenate and
            separate port IDs from/to node IDs
    :param G:
    :return:
    """
    exploded_G = networkx.MultiDiGraph()
    for id, obj in G.nodes_iter(data=True):
      if obj.type == NFFG.TYPE_INFRA:
        static_ports_of_infra = filter(
          lambda p, graph=G: NFFGToolBox.isStaticInfraPort(G, p),
          obj.ports)
        # NOTE: obj.id == p.node.id because of iterating on obj.ports
        static_ports_of_infra_global_ids = map(
          lambda p, c=id_connector_character: id_connector_character.join(
            (str(p.id), str(p.node.id))), static_ports_of_infra)
        exploded_G.add_nodes_from(static_ports_of_infra_global_ids)
        if type(obj.resources.delay) == type(dict):
          # delay is dict of dicts storing the directed distances between ports
          for port1, distances in obj.resources.delay.iteritems():
            for port2, dist in distances.iteritems():
              exploded_G.add_edge(
                id_connector_character.join((str(port1), obj.id)),
                id_connector_character.join((str(port2), obj.id)),
                attr_dict={'delay': dist})
        else:
          # support filling the delay matrix even if the node has only a single
          # delay value, for partial backward compatibility and convenience
          universal_node_delay = obj.resources.delay if obj.resources.delay \
                                                        is not None else 0.0
          for i in static_ports_of_infra_global_ids:
            for j in static_ports_of_infra_global_ids:
              if i != j:
                exploded_G.add_edge(i, j,
                                    attr_dict={'delay': universal_node_delay})
      elif obj.type == NFFG.TYPE_SAP:
        sap_port_found = False
        for p in obj.ports:
          if not sap_port_found:
            exploded_G.add_node(
              id_connector_character.join((str(p.id), p.node.id)))
          else:
            exploded_G.add_node(
              id_connector_character.join((str(p.id), p.node.id)))
            # TODO: In this case multiple nodes in the exploded graph shuold be
            # connected with 0 delay links!
            # log.warn("Multiple ports found in SAP object!")
    # all ports are added as nodes, and the links between the ports denoting the
    # shortest paths inside the infra node are added already.
    # Add links connecting infra nodes and SAPs
    for i, j, k, link in G.edges_iter(data=True, keys=True):
      if link.type == NFFG.TYPE_LINK_STATIC:
        # if a link delay is None, we should take it as 0ms delay.
        link_delay = link.delay if link.delay is not None else 0.0
        exploded_G.add_edge(id_connector_character.join((str(link.src.id), str(i))),
                            id_connector_character.join((str(link.dst.id), str(j))),
                            key=k, attr_dict={'delay': link_delay})
    return exploded_G

  @classmethod
  def extractDistsFromExploded (cls, G, exploded_dists, id_connector_character):
    """
    Extracts the shortest path length matrix from the calculation result on the
    exploded graph structure.
    :param exploded_dists:
    :param id_connector_character:
    :return:
    """
    dist = defaultdict(lambda: defaultdict(lambda: float('inf')))
    min_dist_pairs = defaultdict(lambda: defaultdict(lambda: None))
    for u, obju in G.nodes_iter(data=True):
      # SAPs and Infras are handled the same at this point.
      if obju.type == NFFG.TYPE_INFRA or obju.type == NFFG.TYPE_SAP:
        # a list of (global_port_id, dist_dict) tuples
        possible_dicts = filter(
          lambda tup, original_id=u, sep=id_connector_character:
          original_id == NFFGToolBox.try_to_convert(tup[0].split(sep)[1]),
          exploded_dists.iteritems())
        for v, objv in G.nodes_iter(data=True):
          if objv.type == NFFG.TYPE_INFRA or objv.type == NFFG.TYPE_SAP:
            possible_ending_nodes = filter(
              lambda portid, original_id=v, sep=id_connector_character:
              original_id == NFFGToolBox.try_to_convert(portid.split(sep)[1]),
              exploded_dists.iterkeys())
            # now we need to choose the minimum of the possible distances.
            for starting_node, d in possible_dicts:
              for ending_node in possible_ending_nodes:
                if ending_node in d:
                  if d[ending_node] < dist[NFFGToolBox.try_to_convert(u)][
                    NFFGToolBox.try_to_convert(v)]:
                    dist[NFFGToolBox.try_to_convert(u)][
                      NFFGToolBox.try_to_convert(v)] = d[ending_node]
                    min_dist_pairs[u][v] = (starting_node, ending_node)
    # convert defaultdicts to dicts for safety reasons
    for k in dist:
      dist[k] = dict(dist[k])
    for k in min_dist_pairs:
      min_dist_pairs[k] = dict(min_dist_pairs[k])
    return dict(dist), dict(min_dist_pairs)

  @classmethod
  def extractPathsFromExploded (cls, exploded_paths_dict, min_dist_pairs,
                                id_connector_character):
    """
    Extracts and transforms paths from the matrix of shortest paths 
    calculated on
    the exploded graph structure.
    :param exploded_paths_dict:
    :param min_dist_pairs:
    :param id_connector_character:
    :return:
    """
    min_length_paths = defaultdict(lambda: defaultdict(lambda: None))
    for original_starting_node, d in min_dist_pairs.iteritems():
      for original_ending_node, tup in d.iteritems():
        exploded_path = exploded_paths_dict[tup[0]][tup[1]]
        # get only the exploded IDs, which come from node ID-s
        path_with_only_node_ids = filter(
          lambda lid, sep=id_connector_character: sep in lid, exploded_path)
        # transform them back to the original ID-s
        path_with_original_node_ids = map(
          lambda lid, sep=id_connector_character: lid.split(sep)[1],
          path_with_only_node_ids)
        # the startgin and ending node ID may not be in place
        if path_with_original_node_ids[0] != original_starting_node:
          path_with_original_node_ids.insert(0, original_starting_node)
        if path_with_original_node_ids[-1] != original_ending_node:
          path_with_original_node_ids.append(original_ending_node)

        # a transit infra appears twice in the path after each other, because
        # there was an inbound and an outbound port.
        path_with_original_node_ids_no_duplicates = [
          path_with_original_node_ids[0]]
        for n in path_with_original_node_ids:
          if n != path_with_original_node_ids_no_duplicates[-1]:
            path_with_original_node_ids_no_duplicates.append(n)
        path_with_original_node_ids_no_duplicates_str = map(
          lambda node_id: NFFGToolBox.try_to_convert(node_id),
          path_with_original_node_ids_no_duplicates)
        min_length_paths[NFFGToolBox.try_to_convert(original_starting_node)][
          NFFGToolBox.try_to_convert(original_ending_node)] = \
          path_with_original_node_ids_no_duplicates_str

    # convert embedded default dicts
    for k in min_length_paths:
      min_length_paths[k] = dict(min_length_paths[k])
    return dict(min_length_paths)

  @classmethod
  def shortestPathsInLatency (cls, G, return_paths=False,
                              id_connector_character='&'):
    """
    Calculates shortest pased considering latencies between Infra node ports.
    Uses only the infrastructure part of an NFFG, non Infra nodes doesn't have
    internal forwarding latencies.
    :param G:
    :param return_paths:
    :return:
    """
    exploded_G = NFFGToolBox.explodeGraphWithPortnodes(G,
                                                       id_connector_character)

    exploded_dists = networkx.all_pairs_dijkstra_path_length(exploded_G,
                                                             weight='delay')
    dists, min_dist_pairs = NFFGToolBox.extractDistsFromExploded(G,
                                                                 exploded_dists,
                                                                 id_connector_character)

    if return_paths:
      exploded_paths = networkx.all_pairs_dijkstra_path(exploded_G,
                                                        weight='delay')
      paths = NFFGToolBox.extractPathsFromExploded(exploded_paths,
                                                   min_dist_pairs,
                                                   id_connector_character)
      return paths, dists
    else:
      return dists
