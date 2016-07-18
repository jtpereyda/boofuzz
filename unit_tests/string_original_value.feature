Feature: String.original_value

    Scenario: Same as initial render
        Given A String
        When Calling original_value
        Then Result equals .render()

    Scenario: Same as initial render after mutation
        Given A String
        And Mutated once
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 2 mutations
        Given A String
        And Mutated twice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 3 mutations
        Given A String
        And Mutated thrice
        When Calling original_value
        Then Result equals .render() after .reset()
