import traceback

from boofuzz import constants, exception
from .base_monitor import BaseMonitor


class CallbackMonitor(BaseMonitor):
    """
    New-Style Callback monitor that is used in Session to provide callback-arrays.
    It's purpose is to keep the \\*_callbacks arguments in the session class while
    simplifying the implementation of session by forwarding these callbacks to
    the monitor infrastructure.

    The mapping of arguments to method implementations of this class is as follows:

    - restart_callbacks --> target_restart
    - pre_send_callbacks --> pre_send
    - post_test_case_callbacks --> post_send
    - post_start_target_callbacks --> post_start_target

    All other implemented interface members are stubs only, as no corresponding
    arguments exist in session. In any case, it is probably wiser to implement
    a custom Monitor than to use the callback functions.

    .. versionadded:: 0.2.0
    """

    def __init__(self, on_pre_send=None, on_post_send=None, on_restart_target=None, on_post_start_target=None):
        BaseMonitor.__init__(self)

        self.on_pre_send = on_pre_send if on_pre_send is not None else []
        self.on_post_send = on_post_send if on_post_send is not None else []
        self.on_restart_target = on_restart_target if on_restart_target is not None else []
        self.on_post_start_target = on_post_start_target if on_post_start_target is not None else []

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """This method iterates over all supplied pre send callbacks and executes them.
        Their return values are discarded, exceptions are catched and logged, but otherwise
        discarded.
        """
        try:
            for f in self.on_pre_send:
                fuzz_data_logger.open_test_step('Pre_Send callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="pre_send") + traceback.format_exc()
            )

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """This method iterates over all supplied post send callbacks and executes them.
        Their return values are discarded, exceptions are caught and logged:

        - :class:`BoofuzzTargetConnectionReset <boofuzz.exception.BoofuzzTargetConnectionReset>` will log a failure
        - :class:`BoofuzzTargetConnectionAborted <boofuzz.exception.BoofuzzTargetConnectionAborted>` will log an info
        - :class:`BoofuzzTargetConnectionFailedError <boofuzz.exception.BoofuzzTargetConnectionFailedError>` will log a
          failure
        - :class:`BoofuzzSSLError <boofuzz.exception.BoofuzzSSLError>` will log either info or failure, depending on
          if the session ignores SSL/TLS errors.
        - every other exception is logged as an error.

        All exceptions are discarded after handling.
        """
        try:
            for f in self.on_post_send:
                fuzz_data_logger.open_test_step('Post-test case callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except exception.BoofuzzTargetConnectionReset:
            fuzz_data_logger.log_fail(constants.ERR_CONN_RESET_FAIL)
        except exception.BoofuzzTargetConnectionAborted as e:
            fuzz_data_logger.log_info(
                constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            )
        except exception.BoofuzzTargetConnectionFailedError:
            fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED)
        except exception.BoofuzzSSLError as e:
            if session._ignore_connection_ssl_errors:
                fuzz_data_logger.log_info(str(e))
            else:
                fuzz_data_logger.log_fail(str(e))
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="post_send") + traceback.format_exc()
            )
        finally:
            fuzz_data_logger.open_test_step("Cleaning up connections from callbacks")
        return True

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        """
        This Method tries to restart a target. If no restart callbacks are set,
        it returns false; otherwise it returns true.

        :returns: bool
        """
        try:
            for f in self.on_restart_target:
                fuzz_data_logger.open_test_step('Target restart callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except exception.BoofuzzRestartFailedError:
            raise
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="restart_target") + traceback.format_exc()
            )
        finally:
            fuzz_data_logger.open_test_step("Cleaning up connections from callbacks")
            target.close()
            if session._reuse_target_connection:
                fuzz_data_logger.open_test_step("Reopening target connection")
                target.open()

        if len(self.on_restart_target) > 0:
            return True
        else:
            return False

    def post_start_target(self, target=None, fuzz_data_logger=None, session=None):
        """Called after a target is started or restarted."""
        try:
            for f in self.on_post_start_target:
                fuzz_data_logger.open_test_step('Post-start-target callback: "{0}"'.format(f.__name__))
                f(target=target, fuzz_data_logger=fuzz_data_logger, session=session, sock=target)
        except Exception:
            fuzz_data_logger.log_error(
                constants.ERR_CALLBACK_FUNC.format(func_name="post_start_target") + traceback.format_exc()
            )

    def __repr__(self):
        return "CallbackMonitor#{}[pre=[{}],post=[{}],restart=[{}],post_start_target=[{}]]".format(
            id(self),
            ", ".join([x.__name__ for x in self.on_pre_send]),
            ", ".join([x.__name__ for x in self.on_post_send]),
            ", ".join([x.__name__ for x in self.on_restart_target]),
            ", ".join([x.__name__ for x in self.on_post_start_target]),
        )
