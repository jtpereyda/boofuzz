nbsp = '\xa0';

const StringUtilities = {
    repeat: function (str, times) {
        return (new Array(times + 1)).join(str);
    }
    //other related string functions...
};

function httpGetAsync(theUrl, callback)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() {
        if (xmlHttp.readyState === 4 && xmlHttp.status === 200)
            callback(xmlHttp.responseText);
    };
    xmlHttp.open("GET", theUrl, true); // true for asynchronous
    xmlHttp.send(null);
}

function update_current_run_info(response) {
    let r = JSON.parse(response);

    document.getElementById('current_index').textContent = r.session_info.current_index;
    document.getElementById('num_mutations').textContent = r.session_info.num_mutations;
    document.getElementById('current_index_element').textContent = r.session_info.current_index_element;
    document.getElementById('num_mutations_element').textContent = r.session_info.num_mutations_element;
    document.getElementById('current_element').textContent = r.session_info.current_element;


    let fraction_complete_total = r.session_info.current_index / r.session_info.num_mutations;
    document.getElementById('progress_percentage_total').textContent = progress_percentage(fraction_complete_total);
    document.getElementById('progress_bar_total').textContent = progress_bars(fraction_complete_total);

    let fraction_complete_element = r.session_info.current_index_element / r.session_info.num_mutations_element;
    document.getElementById('progress_percentage_element').textContent = progress_percentage(fraction_complete_element);
    document.getElementById('progress_bar_element').textContent = progress_bars(fraction_complete_element);

    if (r.session_info.is_paused){
        document.getElementById('is_paused_indicator').textContent = 'paused';
        document.getElementById('is_paused_indicator').className = 'paused';
    }
    else {
        document.getElementById('is_paused_indicator').textContent = 'running';
        document.getElementById('is_paused_indicator').className = 'running';

    }

    let new_row;
    let failure_id_link;
    let id_cell;
    let reasons;
    let reasons_cell;
    if (r.session_info.crashes.length > 0) {
        let failures_table = document.getElementById('crash-summary-table');
        let failure_rows = Array.from(failures_table.rows).slice(1);

        failure_rows.forEach(function (row) {
            row.parentNode.removeChild(row);
        });

        for (let i = 0; i < r.session_info.crashes.length; i++) {
            new_row = failures_table.insertRow(failures_table.rows.length);

            id_cell = new_row.insertCell(0);
            id_cell.className = 'fixed';

            failure_id_link = document.createElement('a');
            failure_id_link.setAttribute('href', '/test-case/' + r.session_info.crashes[i].key);
            failure_id_link.textContent = r.session_info.crashes[i].key;
            id_cell.appendChild(failure_id_link);

            reasons_cell = new_row.insertCell();
            reasons = r.session_info.crashes[i].reasons;
            reasons.forEach(function (reason) {
                let reason_item = document.createElement('div');
                reason_item.textContent = reason;
                reasons_cell.appendChild(reason_item);
            })
        }
    }
}


function continually_update_current_run_info()
{
    function update_repeat(response)
    {
        update_current_run_info(response);
        setTimeout(continually_update_current_run_info, 100);
    }
    httpGetAsync('/api/current-run', update_repeat);
}

function progress_bars(fraction){
    return '[' +
        StringUtilities.repeat('=', Math.round(fraction * 50)) +
        StringUtilities.repeat(nbsp, 50 - Math.round(fraction * 50)) + ']';
}

function progress_percentage(fraction){
    return (fraction * 100).toFixed(3) + '%';
}

function start_live_update() {
    initialize_state();
    continually_update_current_run_info();
}

function initialize_state(){
}

document.addEventListener('DOMContentLoaded', start_live_update, false);

