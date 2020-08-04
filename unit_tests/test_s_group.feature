Feature: test_s_group

    Scenario: test_s_group_byte
        Given Scenario with byte can be defined
        When Scenario can be rendered
        Then Scenario output is 0x06
        And Scenario can render all mutations

    Scenario: test_s_group_str
        Given Scenario with str can be defined
        When Scenario can be rendered
        Then Scenario output is 0x06
        And Scenario can render all mutations
