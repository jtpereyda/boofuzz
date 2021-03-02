Feature: Block.original_value

    Scenario: Same as initial render
        Given A Block with contents 0x01
        When Calling original_value
        Then Render() equals 0x01
