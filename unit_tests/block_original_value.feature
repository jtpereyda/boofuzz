Feature: Block.original_value

    Scenario: Same as initial render
        Given A Block with contents
        When Calling original_value
        Then Result equals .render()
