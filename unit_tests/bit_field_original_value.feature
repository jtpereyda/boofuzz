Feature: BitField.original_value

    Scenario: Same as initial render
        Given A BitField
        When Calling original_value
        Then Result equals .render()

    Scenario: Same as initial render after mutation
        Given A BitField
        And Mutated once
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 2 mutations
        Given A BitField
        And Mutated twice
        When Calling original_value
        Then Result equals .render() after .reset()

    Scenario: Same as initial render after 3 mutations
        Given A BitField
        And Mutated thrice
        When Calling original_value
        Then Result equals .render() after .reset()

  Scenario: Render length
    Given A 4 byte BitField with value 100
    When Calling render
    Then len(result) == 4
    And len(uut) == 4

  Scenario: Render length (ascii)
    Given A 4 byte BitField with value 100 and format ascii
    When Calling render
    Then len(result) == 3
    And len(uut) == 3

  Scenario: Render length (ascii) (negative)
    Given A 4 byte BitField with value -1000 and format ascii
    When Calling render
    Then len(result) == 5
    And len(uut) == 5
