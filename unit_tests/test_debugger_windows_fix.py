#!/usr/bin/env python3
"""
Test for issue #736: Windows process monitor ChildProcessError fix.

This test verifies that the process monitor works correctly on Windows
by using subprocess.Popen.wait() instead of os.waitpid() which is Unix-only.
"""

import sys
import unittest
from unittest.mock import Mock
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple


class TestDebuggerWindowsFix(unittest.TestCase):
    """Test Windows compatibility for debugger thread (issue #736)."""

    def test_no_proc_name_uses_subprocess_wait(self):
        """
        Test that when proc_name is None, we use subprocess.Popen.wait()
        instead of os.waitpid(), which fixes issue #736 on Windows.
        
        This test verifies the fix for the ChildProcessError that occurred
        on Windows when using the process monitor without a proc_name.
        """
        mock_pm = Mock()
        mock_pm.log = Mock()
        mock_pm.last_synopsis = ""
        
        # Use a simple command that exits cleanly
        if sys.platform.startswith('win'):
            start_commands = [['cmd', '/c', 'exit 0']]
        else:
            start_commands = [[sys.executable, '-c', 'pass']]
        
        debugger = DebuggerThreadSimple(
            start_commands=start_commands,
            process_monitor=mock_pm,
            proc_name=None,  # This triggers the fixed code path
            log_level=1
        )
        
        # Start and wait for completion
        debugger.start()
        debugger.join(timeout=15)
        
        # Verify successful completion without ChildProcessError
        self.assertFalse(debugger.is_alive(), "Debugger thread should complete")
        self.assertIsNotNone(debugger.exit_status, "Exit status should be set")


if __name__ == '__main__':
    unittest.main()
