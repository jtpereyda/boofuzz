Feature: Block.original_value

    Scenario: Same as initial render
        Given A Block with contents
        When Calling original_value
        Then Result equals .render()

    Scenario: Same as initial render after mutation
        Given A Block with contents
        And Mutated once
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 2 mutations
        Given A Block with contents
        And Mutated twice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 3 mutations
        Given A Block with contents
        And Mutated thrice
        When Calling original_value
        Then Result equals .render() after .reset()
