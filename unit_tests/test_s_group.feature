Feature: test_s_group

    Scenario: test_s_group_byte
        Given Scenario with byte can be defined
        When Scenario can be rendered
        Then Scenario output is 0x06
        And All mutations render

    Scenario: test_s_group_str
        Given Scenario with str can be defined
        When Scenario can be rendered
        Then Scenario output is 0x06
        And All mutations render

    Scenario Outline: test_groups_and_blocks_mutations
        Given Groups and blocks scenario
        When Scenario can be rendered
        Then All mutations render
        And Output of mutation <mutation> is <result>

        Examples:
            | mutation | result |
            | 0        | 0x0211 |
            | 1        | 0x0311 |
            | 2        | 0x0112 |
            | 3        | 0x0113 |
            | 4        | 0x0114 |
            | 5        | 0x0212 |
            | 6        | 0x0213 |
            | 7        | 0x0214 |
            | 8        | 0x0312 |
            | 9        | 0x0313 |
            | 10       | 0x0314 |

    Scenario: test_groups_and_blocks_mutation_count
        Given Groups and blocks scenario
        When Scenario can be rendered
        Then All mutations render
        And There are 11 total mutations
