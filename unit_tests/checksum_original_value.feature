Feature: Checksum.original_value

    Scenario: Same as initial render
        Given A Checksum
        When Calling original_value
        Then Result equals .render()

    Scenario: Same as initial render after mutation
        Given A Checksum
        And Mutated once
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 2 mutations
        Given A Checksum
        And Mutated twice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 3 mutations
        Given A Checksum
        And Mutated thrice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after target block mutation
        Given A Checksum
        And Target block mutated once
        When Calling original_value
        Then Result equals .render() after target block reset()

    Scenario: Same as initial render after 2 target block mutations
        Given A Checksum
        And Target block mutated twice
        When Calling original_value
        Then Result equals .render() after target block reset()

    Scenario: Same as initial render after 3 target block mutations
        Given A Checksum
        And Target block mutated thrice
        When Calling original_value
        Then Result equals .render() after target block reset()

    Scenario: UDP Checksum same as initial render after mutating ipv4_src_block_name
        Given A UDP Checksum
        And ipv4_src_block_name block mutated twice
        When Calling original_value
        Then Result equals .render() after ipv4_src_block_name reset()

    Scenario: UDP Checksum same as initial render after mutating ipv4_dst_block_name
        Given A UDP Checksum
        And ipv4_dst_block_name block mutated twice
        When Calling original_value
        Then Result equals .render() after ipv4_dst_block_name reset()
