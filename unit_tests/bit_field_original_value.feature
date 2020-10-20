Feature: BitField.original_value

    Scenario: Same as initial render
        Given A BitField
        When Calling original_value
        Then Result equals .render()

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
