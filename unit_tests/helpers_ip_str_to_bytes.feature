Feature: helpers.ip_str_to_bytes

    Scenario: Valid IP addresses
        Given Various IP addresses and expected values
        When Calling ip_str_to_bytes
        Then The result is as expected

    Scenario: Invalid IP addresses
        Given Various invalid IP addresses
        When Calling ip_str_to_bytes
        Then A ValueError exception is raised