Feature: Request.original_value

    Scenario: same_as_initial_render_1_block
        Given A Request with one block
        When Calling original_value
        Then Result equals .render()

    Scenario: same_as_initial_render_many_blocks
        Given A Request with multiple blocks
        When Calling original_value
        Then Result equals .render()
