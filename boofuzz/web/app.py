import flask
from flask import Flask, render_template, redirect
import re

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
    return redirect('/')


@app.route('/test-case/<int:crash_id>')
def test_case(crash_id):
    return render_template("test-case.html", crashinfo=app.session.procmon_results.get(crash_id, None), test_case=app.session.test_case_data(crash_id))


@app.route("/")
def index():
    crashes = []
    procmon_result_keys = app.session.procmon_results.keys()
    procmon_result_keys.sort()

    for key in procmon_result_keys:
        val = app.session.procmon_results[key]
        status_bytes = "&nbsp;"

        if key in app.session.netmon_results:
            status_bytes = commify(app.session.netmon_results[key])

        crash = {
            "key": key,
            "value": val.split("\n")[0],
            "status_bytes": status_bytes
        }
        crashes.append(crash)

    # which node (request) are we currently fuzzing.
    if app.session.fuzz_node is not None and app.session.fuzz_node.name:
        current_name = app.session.fuzz_node.name
    else:
        current_name = "[N/A]"

    # render sweet progress bars.
    if app.session.fuzz_node is not None:
        mutant_index = float(app.session.fuzz_node.mutant_index)
        num_mutations = float(app.session.fuzz_node.num_mutations())

        try:
            progress_current = mutant_index / num_mutations
        except ZeroDivisionError:
            progress_current = 0
        num_bars = int(progress_current * 50)
        progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
        progress_current = "%.3f%%" % (progress_current * 100)
    else:
        progress_current = 0
        progress_current_bar = ''
        mutant_index = 0
        num_mutations = 100 # TODO improve template instead of hard coding fake values

    total_mutant_index = float(app.session.total_mutant_index)
    total_num_mutations = float(app.session.total_num_mutations)

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
        "total_num_mutations": commify(int(total_num_mutations)),
    }

    return render_template('index.html', state=state, crashes=crashes)