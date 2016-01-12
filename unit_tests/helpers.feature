Feature: udp_checksum helper

    Scenario: Empty message
        Given: Empty msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3
    
    Scenario: 1 byte
        Given: 1-byte msg b'\xA1'
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0x61C7
        
    Scenario: 2 bytes
        Given: 2-byte msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3
    
    Scenario: 3 bytes
        Given: 3-byte msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3
    
    Scenario: 60 bytes
        Given: 60-byte msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3
    
    Scenario: Max length - 1
        Given: Maximum length - 1 msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3
    
    Scenario: Max length
        Given: Maximum length msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3
    
    Scenario: Max length + 1
        Given: Maximum length + 1 msg
          and: src_addr 192.168.0.12
          and: dst_addr 255.255.255.255
        When: Calling udp_checksum
        Then: The result is 0xC0D3