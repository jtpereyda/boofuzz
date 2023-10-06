import threading

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer

from boofuzz import constants
from boofuzz.web.app import app


class WebApp:
    """Serve fuzz data over HTTP.

    Args:
        session_info (SessionInfo): Object providing information on session
        web_port (int):         Port for monitoring fuzzing campaign via a web browser. Default 26000.
        web_address (string):   Address binded to port for monitoring fuzzing campaign via a web browser.
                                Default 'localhost'.

    .. versionchanged:: 0.4.2
       This class has been moved into the sessions subpackage. The full path is now boofuzz.sessions.web_app.WebApp.
    """

    def __init__(
        self, session_info, web_port=constants.DEFAULT_WEB_UI_PORT, web_address=constants.DEFAULT_WEB_UI_ADDRESS
    ):
        self._session_info = session_info
        self._web_interface_thread = self._build_webapp_thread(port=web_port, address=web_address)
        pass

    def _build_webapp_thread(self, port, address):
        app.session = self._session_info
        http_server = HTTPServer(WSGIContainer(app))
        http_server.listen(port, address=address)
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread

    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc."""
        if not self._web_interface_thread.is_alive():
            # spawn the web interface.
            self._web_interface_thread.start()
