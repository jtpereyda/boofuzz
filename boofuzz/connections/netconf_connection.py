from __future__ import absolute_import

from ncclient import manager

from boofuzz.connections import itarget_connection


class NETCONFConnection(itarget_connection.ITargetConnection):
    """
    ITargetConnection implementation for NETCONF server connections.

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
        self._received_data = None
        self.conn = None
        self.hostkey_verify = hostkey_verify

    def open(self):
        self.conn = manager.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            hostkey_verify=self.hostkey_verify,
        )

    def close(self):
        if self.conn.connected:
            self.conn.close_session()

    def recv(self, max_bytes):
        data = self._received_data
        self._received_data = None

        if data is None:
            data = ""

        return data

    def send(self, data):
        data = data.decode("utf-8")
        self._received_data = self.conn.edit_config(target=self.datastore, config=data)

    def get_raw_conn(self):
        return self.conn

    @property
    def info(self):
        return "host: {host}, port: {port}, username: {username}, datastore: {datastore}, hostkey_verify: {hostkey_verify}".format(
            host=self.host,
            port=self.port,
            username=self.username,
            datastore=self.datastore,
            hostkey_verify=self.hostkey_verify,
        )
