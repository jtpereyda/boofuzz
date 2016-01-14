Feature: helpers.udp_checksum()

    Scenario: Empty message
        Given Empty msg
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x3F3A
    
    Scenario: Msg 1 byte
        Given msg b'\xA1'
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x9E38
        
    Scenario: Msg 2 bytes
        Given msg b'\x00\x00'
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x3F38
    
    Scenario: Msg 3 bytes
        Given msg b'\xF1\xFF\xFF'
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x4E36
    
    Scenario: Msg 60 bytes
        Given msg with 60 bytes
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x3EE9
    
    Scenario: Max length - 1
        Given Maximum length - 1 msg
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0xFF3B
    
    Scenario: Max length
        Given Maximum length msg
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x7F3A
    
    Scenario: Max length + 1
        Given Maximum length + 1 msg
        And src_addr 192.168.0.12
        And dst_addr 255.255.255.255
        When Calling udp_checksum
        Then The result is 0x7F3A  # Same as Max length; see docstring