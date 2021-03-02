Feature: String.original_value

    Scenario: Same as initial render
        Given A String
        When Calling original_value
        Then Result equals .render()
