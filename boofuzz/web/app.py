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


@app.route('/view_crash/<int:crash_id>')
def view_crash(crash_id):
    return render_template("view_crash.html", crashinfo=app.session.procmon_results[crash_id])


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
    if app.session.fuzz_node.name:
        current_name = app.session.fuzz_node.name
    else:
        current_name = "[N/A]"

    # render sweet progress bars.
    mutant_index = float(app.session.fuzz_node.mutant_index)
    num_mutations = float(app.session.fuzz_node.num_mutations())

    try:
        progress_current = mutant_index / num_mutations
    except ZeroDivisionError:
        progress_current = 0
    num_bars = int(progress_current * 50)
    progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
    progress_current = "%.3f%%" % (progress_current * 100)

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
        "current_mutant_index": commify(app.session.fuzz_node.mutant_index),
        "current_name": current_name,
        "current_num_mutations": commify(app.session.fuzz_node.num_mutations()),
        "progress_current": progress_current,
        "progress_current_bar": progress_current_bar,
        "progress_total": progress_total,
        "progress_total_bar": progress_total_bar,
        "total_mutant_index": commify(app.session.total_mutant_index),
        "total_num_mutations": commify(app.session.total_num_mutations),
    }

    return render_template('index.html', state=state, crashes=crashes)