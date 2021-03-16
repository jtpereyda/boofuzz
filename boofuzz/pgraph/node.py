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
from future.builtins import object


class Node(object):
    id = 0
    number = 0

    # general graph attributes
    color = 0xEEF7FF
    border_color = 0xEEEEEE
    label = ""
    shape = "box"

    # gml relevant attributes.
    gml_width = 0.0
    gml_height = 0.0
    gml_pattern = "1"
    gml_stipple = 1
    gml_line_width = 1.0
    gml_type = "rectangle"
    gml_width_shape = 1.0

    # udraw relevant attributes.
    udraw_image = None
    udraw_info = ""

    def __init__(self, node_id=None):
        self.id = node_id
        self.number = 0

        # general graph attributes
        self.color = 0xEEF7FF
        self.border_color = 0xEEEEEE
        self.label = ""
        self.shape = "box"

        # gml relevant attributes.
        self.gml_width = 0.0
        self.gml_height = 0.0
        self.gml_pattern = "1"
        self.gml_stipple = 1
        self.gml_line_width = 1.0
        self.gml_type = "rectangle"
        self.gml_width_shape = 1.0

    def render_node_gml(self):
        """
        Render a node description suitable for use in a GML file using the set internal attributes.

        @rtype:  String
        @return: GML node description.
        """

        # GDE does not like lines longer then approx 250 bytes. within their their own GML files you won't find lines
        # longer then approx 210 bytes. wo we are forced to break long lines into chunks.
        chunked_label = ""
        cursor = 0

        while cursor < len(self.label):
            amount = 200

            # if the end of the current chunk contains a backslash or double-quote, back off some.
            if cursor + amount < len(self.label):
                while self.label[cursor + amount] == "\\" or self.label[cursor + amount] == '"':
                    amount -= 1

            chunked_label += self.label[cursor : cursor + amount] + "\\\n"
            cursor += amount

        # if node width and height were not explicitly specified, make a best effort guess to create something nice.
        if not self.gml_width:
            self.gml_width = len(self.label) * 10

        if not self.gml_height:
            self.gml_height = len(self.label.split()) * 20

        # construct the node definition.
        node = (
            "  node [\n"
            "    id {number}\n"
            '    template "oreas:std:rect"\n'
            '    label "<!--{id:08x}--> {chunked_label}"\n'
            "    graphics [\n"
            "      w {gml_width}\n"
            "      h {gml_height}\n"
            '      fill "#{color:06x}"\n'
            '      line "#{border_color:06x}"\n'
            '      pattern "{gml_pattern}"\n'
            "      stipple {gml_stipple}\n"
            "      lineWidth {gml_line_width}\n"
            '      type "{gml_type}"\n'
            "      width {gml_width_shape}\n"
            "    ]\n"
            "  ]\n".format(
                number=self.number,
                id=self.id,
                gml_width=self.gml_width,
                gml_height=self.gml_height,
                color=self.color,
                border_color=self.border_color,
                gml_pattern=self.gml_pattern,
                gml_stipple=self.gml_stipple,
                gml_line_width=self.gml_line_width,
                gml_type=self.gml_type,
                gml_width_shape=self.gml_width_shape,
                chunked_label=chunked_label,
            )
        )

        return node

    def render_node_graphviz(self):
        """
        Render a node suitable for use in a Pydot graph using the set internal attributes.

        @rtype:  pydot.Node
        @return: Pydot object representing node
        """

        dot_node = pydot.Node(self.id)

        dot_node.obj_dict["attributes"]["label"] = '<<font face="lucida console">{}</font>>'.format(
            self.label.rstrip("\r\n")
        )
        dot_node.obj_dict["attributes"]["label"] = dot_node.obj_dict["attributes"]["label"].replace("\\n", "<br/>")
        dot_node.obj_dict["attributes"]["shape"] = self.shape
        dot_node.obj_dict["attributes"]["color"] = "#{:06x}".format(self.color)
        dot_node.obj_dict["attributes"]["fillcolor"] = "#{:06x}".format(self.color)

        return dot_node

    def render_node_udraw(self, graph):
        """
        Render a node description suitable for use in a uDraw file using the set internal attributes.

        @type  graph: pgraph.Graph
        @param graph: Top level graph object containing the current node

        @rtype:  String
        @return: uDraw node description.
        """

        # translate newlines for uDraw.
        self.label = self.label.replace("\n", "\\n")

        # if an image was specified for this node, update the shape and include the image tag.
        if self.udraw_image:
            self.shape = "image"
            udraw_image = 'a("IMAGE","{}"),'.format(self.udraw_image)
        else:
            udraw_image = ""

        udraw = (
            '\n  l("{id:08x}",\n'
            '    n("",\n'
            "      [\n"
            "        {udraw_image}\n"
            '        a("_GO","{shape}"),\n'
            '        a("COLOR","#{color:08x}"),\n'
            '        a("OBJECT","{label}"),\n'
            '        a("FONTFAMILY","courier"),\n'
            '        a("INFO","{udraw_info}"),\n'
            '        a("BORDER","none")\n'
            "      ]\n"
            "      [\n".format(
                id=self.id,
                udraw_image=udraw_image,
                shape=self.shape,
                color=self.color,
                label=self.label,
                udraw_info=self.udraw_info,
            )
        )

        edges = graph.edges_from(self.id)

        for edge in edges:
            udraw += edge.render_edge_udraw(graph)
            udraw += ","

        if edges:
            udraw = udraw[0:-1]

        udraw += "  ]))"

        return udraw

    def render_node_udraw_update(self):
        """
        Render a node update description suitable for use in a uDraw file using the set internal attributes.

        @rtype:  String
        @return: uDraw node update description.
        """

        # translate newlines for uDraw.
        self.label = self.label.replace("\n", "\\n")

        # if an image was specified for this node, update the shape and include the image tag.
        if self.udraw_image:
            self.shape = "image"
            udraw_image = 'a("IMAGE","{}"),'.format(self.udraw_image)
        else:
            udraw_image = ""

        udraw = (
            '\n  new_node("{id:08x}","",\n'
            "    ["
            "      {udraw_image}\n"
            '      a("_GO","{shape}"),'
            '      a("COLOR","#{color:08x}"),\n'
            '      a("OBJECT","{label}"),\n'
            '      a("FONTFAMILY","courier"),\n'
            '      a("INFO","{udraw_info}"),\n'
            '      a("BORDER","none")\n'
            "    ]\n"
            "  )\n".format(
                id=self.id,
                udraw_image=udraw_image,
                shape=self.shape,
                color=self.color,
                label=self.label,
                udraw_info=self.udraw_info,
            )
        )

        return udraw
