"""Unit tests for Session._test_case_name method (Issue #695)"""
import pytest
from boofuzz import Session, Target
from boofuzz.mutation import Mutation
from boofuzz.mutation_context import MutationContext


class TestTestCaseName:
    """Test that test case names show mutation values, not indices (Issue #695)"""

    def test_test_case_name_uses_value_not_index(self):
        """Test that _test_case_name uses mutation.value instead of mutation.index
        
        This is a regression test for Issue #695 where test case names in the .db
        file showed mutation.index (e.g., "10") instead of mutation.value (e.g., "2038").
        """
        # Create a minimal session
        session = Session(target=Target(connection=None))
        
        # Create a mutation with index=10 and value representing 2038
        # The value is bytes, so we'll use a recognizable pattern
        mutation = Mutation(
            value=b'\x07\xf6',  # 2038 in bytes (0x07f6)
            qualified_name="transaction_id",
            index=10
        )
        
        # Create mutation context
        mutation_context = MutationContext(
            mutations={"transaction_id": mutation},
            message_path=[]
        )
        
        # Get the test case name
        test_case_name = session._test_case_name(mutation_context)
        
        # The test case name should contain the value (as a string representation),
        # NOT the index "10"
        # When mutation.value is formatted, it should show the bytes representation
        assert "b'\\x07\\xf6'" in test_case_name, \
            f"Expected test case name to contain value bytes, got: {test_case_name}"
        
        # Make sure it's NOT showing the index
        # The format is "qualified_name:value", so we check for "transaction_id:10"
        # which would be wrong
        assert "transaction_id:10" not in test_case_name, \
            f"Test case name should not contain index '10', got: {test_case_name}"

    def test_test_case_name_format(self):
        """Test the complete format of test case names"""
        session = Session(target=Target(connection=None))
        
        # Create multiple mutations
        mutation1 = Mutation(
            value=b'\x00\x01',
            qualified_name="field1",
            index=5
        )
        mutation2 = Mutation(
            value=b'\xff\xff',
            qualified_name="field2",
            index=20
        )
        
        mutation_context = MutationContext(
            mutations={"field1": mutation1, "field2": mutation2},
            message_path=[]
        )
        
        test_case_name = session._test_case_name(mutation_context)
        
        # Should contain both field names with their values
        assert "field1:" in test_case_name
        assert "field2:" in test_case_name
        
        # Should contain value representations, not indices
        assert "b'\\x00\\x01'" in test_case_name or "b'\\xff\\xff'" in test_case_name
        
        # Should NOT contain the indices as values
        assert "field1:5" not in test_case_name
        assert "field2:20" not in test_case_name
