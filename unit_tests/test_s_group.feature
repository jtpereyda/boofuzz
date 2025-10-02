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
            | 0        | 0x0111 |
            | 1        | 0x0211 |
            | 2        | 0x0311 |
            | 4        | 0x0112 |
            | 5        | 0x0113 |
            | 6        | 0x0114 |
            | 11       | 0x0211 |
            | 12       | 0x0212 |
            | 13       | 0x0213 |
            | 14       | 0x0214 |
            | 15       | 0x0311 |
            | 16       | 0x0312 |
            | 17       | 0x0313 |
            | 18       | 0x0314 |

    Scenario: test_groups_and_blocks_mutation_count
        Given Groups and blocks scenario
        When Scenario can be rendered
        Then All mutations render
        And There are 19 total mutations

    Scenario: test_default_value_is_fuzzed
        Given Group with default value in values list
        When Scenario can be rendered
        Then All mutations render
        And Mutation values include GET
        And Mutation values include POST
        And There are 2 total mutations
