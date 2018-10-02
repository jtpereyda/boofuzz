BIG_ENDIAN = ">"
LITTLE_ENDIAN = "<"

DEFAULT_WEB_UI_PORT = 26000
DEFAULT_PROCMON_PORT = 26002

RESULTS_DIR = 'boofuzz-results'

ERR_CONN_FAILED_TERMINAL = "Cannot connect to target; target presumed down. Stopping test run. Note: This likely " \
                           "indicates a failure caused by the previous test case. "

ERR_CONN_FAILED = "Cannot connect to target; target presumed down. Note: This likely " \
                  "indicates a failure caused by the previous test case. "

ERR_CONN_ABORTED = "Target connection lost (socket error: {socket_errno} {socket_errmsg}): You may have a " \
                   "network issue, or an issue with firewalls or anti-virus. Try " \
                   "disabling your firewall."

ERR_CONN_RESET = "Target connection reset."

ERR_CONN_RESET_FAIL = "Target connection reset -- considered a failure case when triggered from post_send"
