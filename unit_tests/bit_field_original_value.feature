Feature: BitField.original_value

    Scenario: Same as initial render
        Given A BitField
        When Calling original_value
        Then Result equals .render()

    Scenario: Same as initial render after mutation
        Given A BitField
        And Mutated once
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 2 mutations
        Given A BitField
        And Mutated twice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 3 mutations
        Given A BitField
        And Mutated thrice
        When Calling original_value
        Then Result equals .render() after .reset()
