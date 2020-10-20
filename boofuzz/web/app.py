import re

import flask
from flask import Flask, redirect, render_template

from .. import exception

MAX_LOG_LINE_LEN = 1500

app = Flask(__name__)
app.session = None


def commify(number):
    number = str(number)
    processing = 1
    regex = re.compile(r"^(-?\d+)(\d{3})")
    while processing:
        (number, processing) = regex.subn(r"\1,\2", number)
    return number


@app.route("/togglepause")
def pause():
    # Flip our state
    app.session.is_paused = not app.session.is_paused
    return redirect("/")


@app.route("/test-case/<int:crash_id>")
def test_case(crash_id):
    return render_template(
        "test-case.html",
        crashinfo=app.session.procmon_results.get(crash_id, None),
        test_case=app.session.test_case_data(crash_id),
    )


@app.route("/api/current-test-case")
def current_test_case_update():
    data = {"index": app.session.total_mutant_index, "log_data": _get_log_data(app.session.total_mutant_index)}
    return flask.jsonify(data)


@app.route("/api/test-case/<int:test_case_index>")
def api_test_case(test_case_index):
    data = {"index": test_case_index, "log_data": _get_log_data(test_case_id=test_case_index)}
    return flask.jsonify(data)


def _get_log_data(test_case_id):
    results = []
    try:
        case = app.session.test_case_data(test_case_id)
    except exception.BoofuzzNoSuchTestCase:
        return None
    if case is not None:
        results.append({"css_class": case.css_class, "log_line": case.html_log_line})
        for step in case.steps:
            line = step.html_log_line
            results.append({"css_class": step.css_class, "log_line": line})
    return results


@app.route("/api/current-run")
def index_update():
    data = {
        "session_info": {
            "is_paused": app.session.is_paused,
            "current_index": app.session.total_mutant_index,
            "num_mutations": app.session.total_num_mutations,
            "current_index_element": app.session.mutant_index if app.session is not None else None,
            "num_mutations_element": app.session.fuzz_node.get_num_mutations()
            if app.session.fuzz_node is not None
            else None,
            "current_element": app.session.fuzz_node.name if app.session.fuzz_node is not None else None,
            "crashes": _crash_summary_info(),
        }
    }

    return flask.jsonify(data)


@app.route("/")
def index():
    crashes = _crash_summary_info()

    # which node (request) are we currently fuzzing.
    if app.session.fuzz_node is not None and app.session.fuzz_node.name:
        current_name = app.session.fuzz_node.name
    else:
        current_name = "[N/A]"

    # render sweet progress bars.
    if app.session.fuzz_node is not None:
        mutant_index = float(app.session.mutant_index)
        num_mutations = float(app.session.fuzz_node.get_num_mutations())

        try:
            progress_current = mutant_index / num_mutations
        except ZeroDivisionError:
            progress_current = 0
        num_bars = int(progress_current * 50)
        progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
        progress_current = "%.3f%%" % (progress_current * 100)
    else:
        progress_current = 0
        progress_current_bar = ""
        mutant_index = 0
        num_mutations = 100  # TODO improve template instead of hard coding fake values

    total_mutant_index = float(app.session.total_mutant_index)
    total_num_mutations = app.session.total_num_mutations
    if total_num_mutations is None:
        progress_total = 0
    else:
        try:
            progress_total = total_mutant_index / total_num_mutations
        except ZeroDivisionError:
            progress_total = 0

    num_bars = int(progress_total * 50)
    progress_total_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
    progress_total = "%.3f%%" % (progress_total * 100)

    state = {
        "session": app.session,
        "current_mutant_index": commify(int(mutant_index)),
        "current_name": current_name,
        "current_num_mutations": commify(int(num_mutations)),
        "progress_current": progress_current,
        "progress_current_bar": progress_current_bar,
        "progress_total": progress_total,
        "progress_total_bar": progress_total_bar,
        "total_mutant_index": commify(int(total_mutant_index)),
        "total_num_mutations": commify(int(total_num_mutations)) if total_num_mutations is not None else "N/A",
    }

    return render_template("index.html", state=state, crashes=crashes)


def _crash_summary_info():
    crashes = []
    procmon_result_keys = list(app.session.monitor_results)
    procmon_result_keys.sort()
    for key in procmon_result_keys:
        val = app.session.monitor_results[key]
        status_bytes = "&nbsp;"

        if key in app.session.monitor_data:
            status_bytes = commify(app.session.netmon_results[key])

        crash = {"key": key, "reasons": val, "status_bytes": status_bytes}
        crashes.append(crash)
    return crashes
