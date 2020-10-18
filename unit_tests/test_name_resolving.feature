Feature: test_name_resolving

    Scenario Outline: Complex scenario
      Given Complex request scenario with block <name> block_name <block_name>
      When Scenario is rendered
      Then Scenario output is <result>

      Examples:
      | name     | block_name  | result                           |
      #          |             |   sizer_l1                       |
      #          |             |         vv                       |
      | none     | nothing     | 0xA1A1B102A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | A           | 0xA1A1B102A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | .A          | 0xA1A1B102A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | B1          | 0xA1A1B101A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | .B1         | 0xA1A1B101A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | .C          | 0xA1A1B10BA2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | .C.A        | 0xA1A1B103A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | .C.C.A      | 0xA1A1B104A2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | .           | 0xA1A1B10FA2A2A2B203A3A3A3A3B304 |
      | sizer_l1 | ..test_req  | 0xA1A1B10FA2A2A2B203A3A3A3A3B304 |
      #          |             |             sizer_l2             |
      #          |             |                   vv             |
      | sizer_l2 | A           | 0xA1A1B102A2A2A2B202A3A3A3A3B304 |
      | sizer_l2 | .A          | 0xA1A1B102A2A2A2B203A3A3A3A3B304 |
      | sizer_l2 | B1          | 0xA1A1B102A2A2A2B201A3A3A3A3B304 |
      | sizer_l2 | .B2         | 0xA1A1B102A2A2A2B201A3A3A3A3B304 |
      | sizer_l2 | .C          | 0xA1A1B102A2A2A2B206A3A3A3A3B304 |
      | sizer_l2 | .C.A        | 0xA1A1B102A2A2A2B204A3A3A3A3B304 |
      | sizer_l2 | .C.B3       | 0xA1A1B102A2A2A2B201A3A3A3A3B304 |
      | sizer_l2 | ..C         | 0xA1A1B102A2A2A2B20BA3A3A3A3B304 |
      | sizer_l2 | .           | 0xA1A1B102A2A2A2B20BA3A3A3A3B304 |
      | sizer_l2 | ..          | 0xA1A1B102A2A2A2B20FA3A3A3A3B304 |
      | sizer_l2 | ...test_req | 0xA1A1B102A2A2A2B20FA3A3A3A3B304 |
      #          |             |                         sizer_l3 |
      #          |             |                               vv |
      | sizer_l3 | A           | 0xA1A1B102A2A2A2B203A3A3A3A3B302 |
      | sizer_l3 | .A          | 0xA1A1B102A2A2A2B203A3A3A3A3B304 |
      | sizer_l3 | B1          | 0xA1A1B102A2A2A2B203A3A3A3A3B301 |
      | sizer_l3 | .B3         | 0xA1A1B102A2A2A2B203A3A3A3A3B301 |
      | sizer_l3 | .           | 0xA1A1B102A2A2A2B203A3A3A3A3B306 |
      | sizer_l3 | ..C         | 0xA1A1B102A2A2A2B203A3A3A3A3B306 |
      | sizer_l3 | ..          | 0xA1A1B102A2A2A2B203A3A3A3A3B30B |
      | sizer_l3 | ...C        | 0xA1A1B102A2A2A2B203A3A3A3A3B30B |
      | sizer_l3 | ...         | 0xA1A1B102A2A2A2B203A3A3A3A3B30F |
      | sizer_l3 | ....test_req| 0xA1A1B102A2A2A2B203A3A3A3A3B30F |
      | sizer_l3 | ..C...C..B1 | 0xA1A1B102A2A2A2B203A3A3A3A3B301 |
      # backwards compatibility tests:
      | sizer_l3 | B3          | 0xA1A1B102A2A2A2B203A3A3A3A3B301 |
      | sizer_l3 | B2          | 0xA1A1B102A2A2A2B203A3A3A3A3B301 |

    Scenario Outline: Complex scenario exceptions
      Given Complex request scenario with block <name> block_name <block_name>
      When We try to render the scenario
      Then A BoofuzzNameResolutionError is raised

      Examples:
        | name     | block_name  |
        | sizer_l1 | Z           |
        | sizer_l1 | A.Z         |
        | sizer_l1 | ..A         |
        | sizer_l1 | C..A...A    |
