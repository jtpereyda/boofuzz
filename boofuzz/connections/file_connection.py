from __future__ import absolute_import

import errno
import os

from . import itarget_connection


class FileConnection(itarget_connection.ITargetConnection):
    """Writes each message to a new file within the given directory.

    Args:
        directory: Directory for new message files.
        one_file_only (bool): Set to True to continually overwrite a single file. Can be used in conjunction with a hook
            that processes the file.
    """

    def __init__(self, directory, one_file_only=False):
        self._dirname = directory
        self._file_id = 1
        self._file_handle = None
        self._one_file_only = one_file_only

        try:
            os.mkdir(self._dirname)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            pass

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._file_handle.close()
        if not self._one_file_only:
            self._file_id += 1

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._file_handle = open(os.path.join(self._dirname, str(self._file_id)), "wb")

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            bytes: Received data.
        """
        return b""

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        self._file_handle.write(data)

    @property
    def info(self):
        return "directory: {0}, filename: {1}".format(self._dirname, str(self._file_id))
