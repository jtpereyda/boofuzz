#
# pGRAPH
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import node
import edge
import cluster

import copy

class graph (object):
    '''
    @todo: Add support for clusters
    @todo: Potentially swap node list with a node dictionary for increased performance
    '''

    id       = None
    clusters = []
    edges    = {}
    nodes    = {}

    ####################################################################################################################
    def __init__ (self, id=None):
        '''
        '''

        self.id       = id
        self.clusters = []
        self.edges    = {}
        self.nodes    = {}


    ####################################################################################################################
    def add_cluster (self, cluster):
        '''
        Add a pgraph cluster to the graph.

        @type  cluster: pGRAPH Cluster
        @param cluster: Cluster to add to graph
        '''

        self.clusters.append(cluster)

        return self


    ####################################################################################################################
    def add_edge (self, edge, prevent_dups=True):
        '''
        Add a pgraph edge to the graph. Ensures a node exists for both the source and destination of the edge.

        @type  edge:         pGRAPH Edge
        @param edge:         Edge to add to graph
        @type  prevent_dups: Boolean
        @param prevent_dups: (Optional, Def=True) Flag controlling whether or not the addition of duplicate edges is ok
        '''

        if prevent_dups:
            if self.edges.has_key(edge.id):
                return self

        # ensure the source and destination nodes exist.
        if self.find_node("id", edge.src) and self.find_node("id", edge.dst):
            self.edges[edge.id] = edge

        return self


    ####################################################################################################################
    def add_graph (self, other_graph):
        '''
        Alias of graph_cat(). Concatenate the other graph into the current one.

        @todo: Add support for clusters
        @see:  graph_cat()

        @type  other_graph: pgraph.graph
        @param other_graph: Graph to concatenate into this one.
        '''

        return self.graph_cat(other_graph)


    ####################################################################################################################
    def add_node (self, node):
        '''
        Add a pgraph node to the graph. Ensures a node with the same id does not already exist in the graph.

        @type  node: pGRAPH Node
        @param node: Node to add to graph
        '''

        node.number = len(self.nodes)

        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node

        return self


    ####################################################################################################################
    def del_cluster (self, id):
        '''
        Remove a cluster from the graph.

        @type  id: Mixed
        @param id: Identifier of cluster to remove from graph
        '''

        for cluster in self.clusters:
            if cluster.id == id:
                self.clusters.remove(cluster)
                break

        return self


    ####################################################################################################################
    def del_edge (self, id=None, src=None, dst=None):
        '''
        Remove an edge from the graph. There are two ways to call this routine, with an edge id::

            graph.del_edge(id)

        or by specifying the edge source and destination::

            graph.del_edge(src=source, dst=destination)

        @type  id:  Mixed
        @param id:  (Optional) Identifier of edge to remove from graph
        @type  src: Mixed
        @param src: (Optional) Source of edge to remove from graph
        @type  dst: Mixed
        @param dst: (Optional) Destination of edge to remove from graph
        '''

        if not id:
            id = (src << 32) + dst

        if self.edges.has_key(id):
            del self.edges[id]

        return self


    ####################################################################################################################
    def del_graph (self, other_graph):
        '''
        Alias of graph_sub(). Remove the elements shared between the current graph and other graph from the current
        graph.

        @todo: Add support for clusters
        @see:  graph_sub()

        @type  other_graph: pgraph.graph
        @param other_graph: Graph to diff/remove against
        '''

        return self.graph_sub(other_graph)


    ####################################################################################################################
    def del_node (self, id):
        '''
        Remove a node from the graph.

        @type  node_id: Mixed
        @param node_id: Identifier of node to remove from graph
        '''

        if self.nodes.has_key(id):
            del self.nodes[id]

        return self


    ####################################################################################################################
    def edges_from (self, id):
        '''
        Enumerate the edges from the specified node.

        @type  id: Mixed
        @param id: Identifier of node to enumerate edges from

        @rtype:  List
        @return: List of edges from the specified node
        '''

        return [edge for edge in self.edges.values() if edge.src == id]


    ####################################################################################################################
    def edges_to (self, id):
        '''
        Enumerate the edges to the specified node.

        @type  id: Mixed
        @param id: Identifier of node to enumerate edges to

        @rtype:  List
        @return: List of edges to the specified node
        '''

        return [edge for edge in self.edges.values() if edge.dst == id]


    ####################################################################################################################
    def find_cluster (self, attribute, value):
        '''
        Find and return the cluster with the specified attribute / value pair.

        @type  attribute: String
        @param attribute: Attribute name we are looking for
        @type  value:     Mixed
        @param value:     Value of attribute we are looking for

        @rtype:  Mixed
        @return: Cluster, if attribute / value pair is matched. None otherwise.
        '''

        for cluster in self.clusters:
            if hasattr(cluster, attribute):
                if getattr(cluster, attribute) == value:
                    return cluster

        return None


    ####################################################################################################################
    def find_cluster_by_node (self, attribute, value):
        '''
        Find and return the cluster that contains the node with the specified attribute / value pair.

        @type  attribute: String
        @param attribute: Attribute name we are looking for
        @type  value:     Mixed
        @param value:     Value of attribute we are looking for

        @rtype:  Mixed
        @return: Cluster, if node with attribute / value pair is matched. None otherwise.
        '''

        for cluster in self.clusters:
            for node in cluster:
                if hasattr(node, attribute):
                    if getattr(node, attribute) == value:
                        return cluster

        return None


    ####################################################################################################################
    def find_edge (self, attribute, value):
        '''
        Find and return the edge with the specified attribute / value pair.

        @type  attribute: String
        @param attribute: Attribute name we are looking for
        @type  value:     Mixed
        @param value:     Value of attribute we are looking for

        @rtype:  Mixed
        @return: Edge, if attribute / value pair is matched. None otherwise.
        '''

        # if the attribute to search for is the id, simply return the edge from the internal hash.
        if attribute == "id" and self.edges.has_key(value):
            return self.edges[value]

        # step through all the edges looking for the given attribute/value pair.
        else:
            for edge in self.edges.values():
                if hasattr(edge, attribute):
                    if getattr(edge, attribute) == value:
                        return edge

        return None


    ####################################################################################################################
    def find_node (self, attribute, value):
        '''
        Find and return the node with the specified attribute / value pair.

        @type  attribute: String
        @param attribute: Attribute name we are looking for
        @type  value:     Mixed
        @param value:     Value of attribute we are looking for

        @rtype:  Mixed
        @return: Node, if attribute / value pair is matched. None otherwise.
        '''

        # if the attribute to search for is the id, simply return the node from the internal hash.
        if attribute == "id" and self.nodes.has_key(value):
            return self.nodes[value]

        # step through all the nodes looking for the given attribute/value pair.
        else:
            for node in self.nodes.values():
                if hasattr(node, attribute):
                    if getattr(node, attribute) == value:
                        return node

        return None


    ####################################################################################################################
    def graph_cat (self, other_graph):
        '''
        Concatenate the other graph into the current one.

        @todo: Add support for clusters

        @type  other_graph: pgraph.graph
        @param other_graph: Graph to concatenate into this one.
        '''

        for other_node in other_graph.nodes.values():
            self.add_node(other_node)

        for other_edge in other_graph.edges.values():
            self.add_edge(other_edge)

        return self


    ####################################################################################################################
    def graph_down (self, from_node_id, max_depth=-1):
        '''
        Create a new graph, looking down, from the specified node id to the specified depth.

        @type  from_node_id: pgraph.node
        @param from_node_id: Node to use as start of down graph
        @type  max_depth:    Integer
        @param max_depth:    (Optional, Def=-1) Number of levels to include in down graph (-1 for infinite)

        @rtype:  pgraph.graph
        @return: Down graph around specified node.
        '''

        down_graph = graph()
        from_node  = self.find_node("id", from_node_id)

        if not from_node:
            print "unable to resolve node %08x" % from_node_id
            raise Exception

        levels_to_process = []
        current_depth     = 1

        levels_to_process.append([from_node])

        for level in levels_to_process:
            next_level = []

            if current_depth > max_depth and max_depth != -1:
                break

            for node in level:
                down_graph.add_node(copy.copy(node))

                for edge in self.edges_from(node.id):
                    to_add = self.find_node("id", edge.dst)

                    if not down_graph.find_node("id", edge.dst):
                        next_level.append(to_add)

                    down_graph.add_node(copy.copy(to_add))
                    down_graph.add_edge(copy.copy(edge))

            if next_level:
                levels_to_process.append(next_level)

            current_depth += 1

        return down_graph


    ####################################################################################################################
    def graph_intersect (self, other_graph):
        '''
        Remove all elements from the current graph that do not exist in the other graph.

        @todo: Add support for clusters

        @type  other_graph: pgraph.graph
        @param other_graph: Graph to intersect with
        '''

        for node in self.nodes.values():
            if not other_graph.find_node("id", node.id):
                self.del_node(node.id)

        for edge in self.edges.values():
            if not other_graph.find_edge("id", edge.id):
                self.del_edge(edge.id)

        return self


    ####################################################################################################################
    def graph_proximity (self, center_node_id, max_depth_up=2, max_depth_down=2):
        '''
        Create a proximity graph centered around the specified node.

        @type  center_node_id: pgraph.node
        @param center_node_id: Node to use as center of proximity graph
        @type  max_depth_up:   Integer
        @param max_depth_up:   (Optional, Def=2) Number of upward levels to include in proximity graph
        @type  max_depth_down: Integer
        @param max_depth_down: (Optional, Def=2) Number of downward levels to include in proximity graph

        @rtype:  pgraph.graph
        @return: Proximity graph around specified node.
        '''

        prox_graph = self.graph_down(center_node_id, max_depth_down)
        prox_graph.add_graph(self.graph_up(center_node_id, max_depth_up))

        return prox_graph


    ####################################################################################################################
    def graph_sub (self, other_graph):
        '''
        Remove the elements shared between the current graph and other graph from the current
        graph.

        @todo: Add support for clusters

        @type  other_graph: pgraph.graph
        @param other_graph: Graph to diff/remove against
        '''

        for other_node in other_graph.nodes.values():
            self.del_node(other_node.id)

        for other_edge in other_graph.edges.values():
            self.del_edge(None, other_edge.src, other_edge.dst)

        return self


    ####################################################################################################################
    def graph_up (self, from_node_id, max_depth=-1):
        '''
        Create a new graph, looking up, from the specified node id to the specified depth.

        @type  from_node_id: pgraph.node
        @param from_node_id: Node to use as start of up graph
        @type  max_depth:    Integer
        @param max_depth:    (Optional, Def=-1) Number of levels to include in up graph (-1 for infinite)

        @rtype:  pgraph.graph
        @return: Up graph to the specified node.
        '''

        up_graph  = graph()
        from_node = self.find_node("id", from_node_id)

        levels_to_process = []
        current_depth     = 1

        levels_to_process.append([from_node])

        for level in levels_to_process:
            next_level = []

            if current_depth > max_depth and max_depth != -1:
                break

            for node in level:
                up_graph.add_node(copy.copy(node))

                for edge in self.edges_to(node.id):
                    to_add = self.find_node("id", edge.src)

                    if not up_graph.find_node("id", edge.src):
                        next_level.append(to_add)

                    up_graph.add_node(copy.copy(to_add))
                    up_graph.add_edge(copy.copy(edge))

            if next_level:
                levels_to_process.append(next_level)

            current_depth += 1

        return up_graph


    ####################################################################################################################
    def render_graph_gml (self):
        '''
        Render the GML graph description.

        @rtype:  String
        @return: GML graph description.
        '''

        gml  = 'Creator "pGRAPH - Pedram Amini <pedram.amini@gmail.com>"\n'
        gml += 'directed 1\n'

        # open the graph tag.
        gml += 'graph [\n'

        # add the nodes to the GML definition.
        for node in self.nodes.values():
            gml += node.render_node_gml(self)

        # add the edges to the GML definition.
        for edge in self.edges.values():
            gml += edge.render_edge_gml(self)

        # close the graph tag.
        gml += ']\n'

        """
        TODO: Complete cluster rendering
        # if clusters exist.
        if len(self.clusters):
            # open the rootcluster tag.
            gml += 'rootcluster [\n'

            # add the clusters to the GML definition.
            for cluster in self.clusters:
                gml += cluster.render()

            # add the clusterless nodes to the GML definition.
            for node in self.nodes:
                if not self.find_cluster_by_node("id", node.id):
                    gml += '    vertex "%d"\n' % node.id

            # close the rootcluster tag.
            gml += ']\n'
        """

        return gml


    ####################################################################################################################
    def render_graph_graphviz (self):
        '''
        Render the graphviz graph structure.

        @rtype:  pydot.Dot
        @return: Pydot object representing entire graph
        '''

        import pydot

        dot_graph = pydot.Dot()

        for node in self.nodes.values():
            dot_graph.add_node(node.render_node_graphviz(self))

        for edge in self.edges.values():
            dot_graph.add_edge(edge.render_edge_graphviz(self))

        return dot_graph


    ####################################################################################################################
    def render_graph_udraw (self):
        '''
        Render the uDraw graph description.

        @rtype:  String
        @return: uDraw graph description.
        '''

        udraw = '['

        # render each of the nodes in the graph.
        # the individual nodes will handle their own edge rendering.
        for node in self.nodes.values():
            udraw += node.render_node_udraw(self)
            udraw += ','

        # trim the extraneous comment and close the graph.
        udraw = udraw[0:-1] + ']'

        return udraw


    ####################################################################################################################
    def render_graph_udraw_update (self):
        '''
        Render the uDraw graph update description.

        @rtype:  String
        @return: uDraw graph description.
        '''

        udraw = '['

        for node in self.nodes.values():
            udraw += node.render_node_udraw_update()
            udraw += ','

        for edge in self.edges.values():
            udraw += edge.render_edge_udraw_update()
            udraw += ','

        # trim the extraneous comment and close the graph.
        udraw = udraw[0:-1] + ']'

        return udraw


    ####################################################################################################################
    def update_node_id (self, current_id, new_id):
        '''
        Simply updating the id attribute of a node will sever the edges to / from the given node. This routine will
        correctly update the edges as well.

        @type  current_id: Long
        @param current_id: Current ID of node whose ID we want to update
        @type  new_id:     Long
        @param new_id:     New ID to update to.
        '''

        if not self.nodes.has_key(current_id):
            return

        # update the node.
        node = self.nodes[current_id]
        del self.nodes[current_id]
        node.id = new_id
        self.nodes[node.id] = node

        # update the edges.
        for edge in [edge for edge in self.edges.values() if current_id in (edge.src, edge.dst)]:
            del self.edges[edge.id]

            if edge.src == current_id:
                edge.src = new_id
            if edge.dst == current_id:
                edge.dst = new_id

            edge.id = (edge.src << 32) + edge.dst

            self.edges[edge.id] = edge


    ####################################################################################################################
    def sorted_nodes (self):
        '''
        Return a list of the nodes within the graph, sorted by id.

        @rtype:  List
        @return: List of nodes, sorted by id.
        '''

        node_keys = self.nodes.keys()
        node_keys.sort()

        return [self.nodes[key] for key in node_keys]
