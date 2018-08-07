nbsp = '\xa0';
let failure_map = {};

const StringUtilities = {
    repeat: function (str, times) {
        return (new Array(times + 1)).join(str);
    }
    //other related string functions...
};

function update_current_run_info(response) {
    document.getElementById('current_index').textContent = response.session_info.current_index;
    document.getElementById('num_mutations').textContent = response.session_info.num_mutations;
    document.getElementById('current_index_element').textContent = response.session_info.current_index_element;
    document.getElementById('num_mutations_element').textContent = response.session_info.num_mutations_element;
    document.getElementById('current_element').textContent = response.session_info.current_element;


    let fraction_complete_total = response.session_info.current_index / response.session_info.num_mutations;
    document.getElementById('progress_percentage_total').textContent = progress_percentage(fraction_complete_total);
    document.getElementById('progress_bar_total').textContent = progress_bars(fraction_complete_total);

    let fraction_complete_element = response.session_info.current_index_element / response.session_info.num_mutations_element;
    document.getElementById('progress_percentage_element').textContent = progress_percentage(fraction_complete_element);
    document.getElementById('progress_bar_element').textContent = progress_bars(fraction_complete_element);

    if (response.session_info.is_paused){
        document.getElementById('is_paused_indicator').textContent = 'paused';
        document.getElementById('is_paused_indicator').className = 'paused';
    }
    else {
        document.getElementById('is_paused_indicator').textContent = 'running';
        document.getElementById('is_paused_indicator').className = 'running';

    }

    if (response.session_info.crashes.length > 0) {
        let failures_table = document.getElementById('crash-summary-table');

        for (let i = 0; i < response.session_info.crashes.length; i++) {
            let key = response.session_info.crashes[i].key;
            if (!(key in failure_map))
            {
                let reasons = response.session_info.crashes[i].reasons;
                failure_map[key] = reasons;
                let new_row = failures_table.insertRow(failures_table.rows.length);

                let id_cell = new_row.insertCell(0);
                id_cell.className = 'fixed';

                let failure_id_link = document.createElement('a');
                failure_id_link.setAttribute('href', '/test-case/' + key);
                failure_id_link.textContent = key;
                id_cell.appendChild(failure_id_link);

                let reasons_cell = new_row.insertCell();
                reasons.forEach(function (reason) {
                    let reason_item = document.createElement('div');
                    reason_item.textContent = reason;
                    reasons_cell.appendChild(reason_item);
                })
            }
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
    function _repeat_only()
    {
        setTimeout(continually_update_current_run_info, 100);
    }
    fetch(new Request('/api/current-run'), {method: 'GET'})
    .then(function(response) { return response.json() })
    .then(update_repeat)
    .catch(_repeat_only);
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

function read_failure_map_from_dom() {
    let failures_table = document.getElementById('crash-summary-table');
    let failure_rows = Array.from(failures_table.rows).slice(1);
    failure_rows.forEach(function (row) {
        let key = row.cells[0].textContent.trim();
        failure_map[key] = row.cells[1].textContent.trim();
    });
}

function initialize_state(){
    read_failure_map_from_dom();
}

document.addEventListener('DOMContentLoaded', start_live_update, false);
