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

import pydot


class Edge(object):
    id = None
    src = None
    dst = None

    # general graph attributes.
    color = 0x000000
    label = ""

    # gml relevant attributes.
    gml_arrow = "none"
    gml_stipple = 1
    gml_line_width = 1.0

    def __init__(self, src, dst):
        """
        Class constructor.

        @type  src: Mixed
        @param src: Edge source
        @type  dst: Mixed
        @param dst: Edge destination
        """

        # the unique id for any edge (provided that duplicates are not allowed) is the combination of the source and
        # the destination stored as a long long.
        self.id = (src << 32) + dst
        self.src = src
        self.dst = dst

        # general graph attributes.
        self.color = 0x000000
        self.label = ""

        # gml relevant attributes.
        self.gml_arrow = "none"
        self.gml_stipple = 1
        self.gml_line_width = 1.0

    def render_edge_gml(self, graph):
        """
        Render an edge description suitable for use in a GML file using the set internal attributes.

        @type  graph: pgraph.Graph
        @param graph: Top level graph object containing the current edge

        @rtype:  String
        @return: GML edge description
        """

        src = graph.find_node("id", self.src)
        dst = graph.find_node("id", self.dst)

        # ensure nodes exist at the source and destination of this edge.
        if not src or not dst:
            return ""

        edge = """
          edge [
            source %(srcNumber)d
            target %(dstNumber)d
            generalization 0
            graphics [
              type "line"
              arrow "%(gml_arrow)s"
              stripple %(gml_stipple)d
              linWidth %(gml_line_width)f
              fill "#%(color)06x"
            ]
          ]
        """ % {
            "color": self.color,
            "srcNumber": src.number,
            "dstNumber": dst.number,
            "gml_arrow": self.gml_arrow,
            "gml_stipple": self.gml_stipple,
            "gml_line_width": self.gml_line_width
        }

        return edge

    def render_edge_graphviz(self):
        """
        Render an edge suitable for use in a Pydot graph using the set internal attributes.

        @rtype:  pydot.Edge()
        @return: Pydot object representing edge
        """

        # no need to validate if nodes exist for src/dst. graphviz takes care of that for us transparently.

        dot_edge = pydot.Edge(self.src, self.dst)

        if self.label:
            dot_edge.label = self.label

        dot_edge.color = "#%06x" % self.color

        return dot_edge

    def render_edge_udraw(self, graph):
        """
        Render an edge description suitable for use in a GML file using the set internal attributes.

        @type  graph: pgraph.Graph
        @param graph: Top level graph object containing the current edge

        @rtype:  String
        @return: GML edge description
        """

        src = graph.find_node("id", self.src)
        dst = graph.find_node("id", self.dst)

        # ensure nodes exist at the source and destination of this edge.
        if not src or not dst:
            return ""

        # translate newlines for uDraw.
        self.label = self.label.replace("\n", "\\n")

        udraw = """
        l("%(src)08x->%(dst)08x",
          e("",
            [
              a("EDGECOLOR","#%(color)06x"),
              a("OBJECT","%(label)s")
            ],
            r("%(dst)08x")
          )
        )
        """ % {
            "src": self.src,
            "dst": self.dst,
            "color": self.color,
            "label": self.label,

        }

        return udraw

    def render_edge_udraw_update(self):
        """
        Render an edge update description suitable for use in a GML file using the set internal attributes.

        @rtype:  String
        @return: GML edge update description
        """

        # translate newlines for uDraw.
        self.label = self.label.replace("\n", "\\n")

        udraw = """
        new_edge("%(src)08x->%(dst)08x","",
          [
            a("EDGECOLOR","#%(color)06x"),
            a("OBJECT","%(label)s")
          ]
          "%(src)08x","%(dst)08x"
        )
        """ % {
            "src": self.src,
            "dst": self.dst,
            "color": self.color,
            "label": self.label,
        }

        return udraw