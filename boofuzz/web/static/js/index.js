nbsp = '\xa0';
let failure_map = {};
let test_case_log_snap = true;
let test_case_log_index = 0;
let last_test_case_log_response = "";

const StringUtilities = {
    repeat: function (str, times) {
        return (new Array(times + 1)).join(str);
    }
};

function update_current_run_info(response) {
    document.getElementById('current_index').textContent = response.session_info.current_index.toLocaleString();
    document.getElementById('num_mutations').textContent = (response.session_info.num_mutations || "many").toLocaleString();
    document.getElementById('current_index_element').textContent = response.session_info.current_index_element.toLocaleString();
    document.getElementById('num_mutations_element').textContent = response.session_info.num_mutations_element.toLocaleString();
    document.getElementById('current_element').textContent = response.session_info.current_element + ":";
    document.getElementById('current_test_case_name').textContent = response.session_info.current_test_case_name;
    document.getElementById('exec_speed').textContent = response.session_info.exec_speed.toFixed(1) + "/sec";
    document.getElementById('run_time').textContent = response.session_info.runtime.toFixed(0) + " sec";


    if (response.session_info.num_mutations != null) {
        let fraction_complete_total = response.session_info.current_index / response.session_info.num_mutations;
        document.getElementById('progress_percentage_total').textContent = progress_percentage(fraction_complete_total);
        document.getElementById('progress_bar_total').textContent = progress_bars(fraction_complete_total);
    }
    else {
        document.getElementById('progress_percentage_total').textContent = "";
        document.getElementById('progress_bar_total').textContent = "";
    }

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
                failure_id_link.textContent = key;
                failure_id_link.classList.add('link');
                failure_id_link.addEventListener('click', function(){logNavGoTo(key)}, false);
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

function response_changed(old_response, new_response) {
    // deep equals would be appropriate and more maintainable, but at time of writing we didn't want to add a JS library
    return old_response["index"] !== new_response["index"] ||
        old_response["log_data"].length !== new_response["log_data"].length;
}

function update_current_test_case_log(response) {
    if (!response_changed(response, last_test_case_log_response)) {
        return
    }
    last_test_case_log_response = response;

    logUpdateIndex(response.index);

    // Create log table entries
    let new_entries = document.createElement('tbody');
    if (response.log_data === null){
        let new_span = document.createElement('span');
        new_span.textContent = 'Test case does not exist'
        let new_td = document.createElement('td');
        let new_tr = document.createElement('tr');
        new_td.appendChild(new_span);
        new_tr.appendChild(new_td);
        new_entries.appendChild(new_tr);
    }
    else{
        response.log_data.forEach(function(log_entry) {
            let new_span = document.createElement('span');
            new_span.setAttribute('class', log_entry.css_class);
            new_span.textContent = log_entry.log_line;
            let new_td = document.createElement('td');
            let new_tr = document.createElement('tr');
            new_td.appendChild(new_span);
            new_tr.appendChild(new_td);
            new_entries.appendChild(new_tr);
        });
    }

    // Insert log table entries
    let test_cases_table = document.getElementById('test-steps-table');
    while (test_cases_table.firstChild){
        test_cases_table.removeChild(test_cases_table.firstChild);
    }
    test_cases_table.appendChild(new_entries);
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

function continually_update_current_test_case_log()
{
    function update_repeat(response)
    {
        if (test_case_log_snap) { // This check is important as one may un-check the box before the response arrives
            update_current_test_case_log(response);
        }
        setTimeout(continually_update_current_test_case_log, 100);
    }
    function update_same_case_repeat(response)
    {
        update_current_test_case_log(response);
        setTimeout(continually_update_current_test_case_log, 100);
    }
    function _repeat_only()
    {
        setTimeout(continually_update_current_test_case_log, 100);
    }
    if (test_case_log_snap) {
        fetch(new Request('/api/current-test-case'), {method: 'GET'})
            .then(function(response) { return response.json() })
            .then(update_repeat)
            .catch(_repeat_only);
    }
    else {
        fetch(new Request(`/api/test-case/${test_case_log_index}`), {method: 'GET'})
            .then(function(response) { return response.json() })
            .then(update_same_case_repeat)
            .catch(_repeat_only);
    }
}

function progress_bars(fraction){
    return '[' +
        StringUtilities.repeat('=', Math.round(Math.min(fraction, 1) * 50)) +
        StringUtilities.repeat(nbsp, 50 - Math.round(Math.min(fraction, 1) * 50)) + ']';
}

function progress_percentage(fraction){
    return (fraction * 100).toFixed(3) + '%';
}

function start_live_update() {
    initialize_state();
    continually_update_current_run_info();
    continually_update_current_test_case_log();
}

function read_failure_map_from_dom() {
    let failures_table = document.getElementById('crash-summary-table');
    let failure_rows = Array.from(failures_table.rows).slice(1);
    failure_rows.forEach(function (row) {
        let key = row.cells[0].textContent.trim();
        failure_map[key] = row.cells[1].textContent.trim();
    });
}

function set_failure_link_event_handlers() {
    let failures_table = document.getElementById('crash-summary-table');
    let failure_rows = Array.from(failures_table.rows).slice(1);
    failure_rows.forEach(function (row) {
        let key = row.cells[0].textContent.trim();
        row.cells[0].getElementsByClassName('link')[0].addEventListener('click', function(){logNavGoTo(Number(key))}, false);
    });
}

function initialize_state(){
    read_failure_map_from_dom();
}

function logSnapChangeHandler(event){
    test_case_log_snap = event.target.checked;
    if (test_case_log_snap) {
        document.getElementById('test-case-log-index-input').value = '';
    }
}

function logInputChangeHandler(event){
    logNavGoTo(event.target.value);
}

function logNavMove(num){
    logNavGoTo(test_case_log_index + num);
}

function logNavGoTo(num){
    logUpdateSnap(false);
    if (num > 0) {
        updateIndexToFetch(num);
    }
}

function logUpdateSnap(on){
    test_case_log_snap = on;
    document.getElementById('test-case-log-snap').checked = on;
}

function logUpdateIndex(num){
    updateIndexToFetch(num);

    let test_case_log_title_index = document.getElementById('test-case-log-title-index');
    test_case_log_title_index.textContent = num;

}

function updateIndexToFetch(num){
    test_case_log_index = num;

    let index_input = document.getElementById('test-case-log-index-input');
    if (document.activeElement !== index_input){
        index_input.value = num;
    }
}

function initPage(){
    test_case_log_snap = document.getElementById('test-case-log-snap').checked;
    document.getElementById('test-case-log-index-input').addEventListener('change', logInputChangeHandler, false);
    document.getElementById('test-case-log-snap').addEventListener('click', logSnapChangeHandler, false);
    document.getElementById('test-case-log-left').addEventListener('click', function(){logNavMove(-1)}, false);
    document.getElementById('test-case-log-right').addEventListener('click', function(){logNavMove(1)} , false);
    set_failure_link_event_handlers();
    start_live_update();
}

document.addEventListener('DOMContentLoaded', initPage, false);
