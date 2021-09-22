import warnings

from boofuzz.connections import itarget_connection


class NETCONFConnection(itarget_connection.ITargetConnection):
    """
    ITargetConnection implementation for NETCONF server connections.
    Unlike ITargetConnection, NETCONFConnection works with utf-8 encoded strings
    instead of bytes.

    Args:
        host (str): IP address of NETCONF server.
        port (int): port of NETCONF server.
        username (str): NETCONF server login username.
        password (str): NETCONF server login password.
        datastore (str): NETCONF server datastore to send fuzz requests to.
        hostkey_verify(bool): Verify SSH host key when connecting to NETCONF server
    """

    def __init__(self, host, port, username, password, datastore, hostkey_verify):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.datastore = datastore
        self.hostkey_verify = hostkey_verify
        self._received_data = None
        self._conn = None

    def open(self):
        try:
            from ncclient import manager  # pytype: disable=import-error
        except ImportError:
            warnings.warn("Importing ncclient package failed. Please install it using pip.", UserWarning)
            raise

        self._conn = manager.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            hostkey_verify=self.hostkey_verify,
        )

    def close(self):
        if self._conn.connected:
            self._conn.close_session()

    def recv(self, max_bytes):
        """
        Receive data from the NETCONF server.

        Args:
            max_bytes (int): Maximum number of bytes to receive. Currently ignored.

        Returns:
            str: utf-8 encoded XML response
        """

        data = self._received_data
        self._received_data = None

        if data is None:
            data = ""

        return data

    def send(self, data):
        """
        Send an edit-config request to the NETCONF server.

        Args:
            data (str): XML data for an XML edit_config request. Should be a
            string with utf-8 encoding.
        """

        data = data.decode("utf-8")

        # store data for later recv() calls
        self._received_data = self._conn.edit_config(target=self.datastore, config=data)

    def get_raw_conn(self):
        return self._conn

    @property
    def info(self):
        return (
            "host: {host}, port: {port}, username: {username},"
            " datastore: {datastore}, hostkey_verify: {hostkey_verify}".format(
                host=self.host,
                port=self.port,
                username=self.username,
                datastore=self.datastore,
                hostkey_verify=self.hostkey_verify,
            )
        )
