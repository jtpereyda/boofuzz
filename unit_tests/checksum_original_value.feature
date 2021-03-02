Feature: Checksum.original_value

    Scenario: Same as initial render
        Given A Checksum
        When Calling original_value
        Then Render() equals 0x66215e00
