Feature: Size.original_value

    Scenario: Same as initial render
        Given A Size
        When Calling original_value
        Then Result equals .render()

    Scenario: Same as initial render after mutation
        Given A Size
        And Mutated once
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 2 mutations
        Given A Size
        And Mutated twice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 3 mutations
        Given A Size
        And Mutated thrice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after target block mutation
        Given A Size whose target block will change size upon mutation
        And Target block mutated once
        When Calling original_value
        Then Result equals .render() after Request reset()

    Scenario: Same as initial render after 2 target block mutations
        Given A Size whose target block will change size upon mutation
        And Target block mutated twice
        When Calling original_value
        Then Result equals .render() after Request reset()

    Scenario: Same as initial render after 3 target block mutations
        Given A Size whose target block will change size upon mutation
        And Target block mutated thrice
        When Calling original_value
        Then Result equals .render() after Request reset()
