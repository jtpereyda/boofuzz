Feature: Size.original_value

    Scenario: Same as initial render
        Given A Size
        When Calling original_value
        Then Result equals .render()
