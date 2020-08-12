Feature: test_name_resolving

    Scenario Outline: A flat scenario
        Given A flat scenario with block_name <block_name>
        When Scenario can be rendered
        Then Scenario output is 0xffff01ff
        And Scenario can render all mutations

        Examples:
        | block_name                        |
        | 1_static_byte                     |
        | test_name_resolving.1_static_byte |


    Scenario Outline: A 1 deep scenario
        Given A 1 deep scenario with block_name <block_name>
        When Scenario can be rendered
        Then Scenario output is 0xff01feff
        And Scenario can render all mutations

        Examples:
        | block_name                               |
        | 1_deep                                   |
        | 1_deep.1_static_byte                     |
        | test_name_resolving.1_deep.1_static_byte |


    Scenario Outline: A 1 deep higher scenario
        Given A 1 deep higher scenario with block_name <block_name>
        When Scenario can be rendered
        Then Scenario output is 0xff01feff
        And Scenario can render all mutations

        Examples:
        | block_name                               |
        | _parent.1_byte_root                      |
        | test_name_resolving.1_byte_root          |
