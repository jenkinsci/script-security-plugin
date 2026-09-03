Behaviour.specify('.script-approval-approve-link', 'ScriptApproval.FormValidationPageDecorator', 0, function (element) {
    element.onclick = function (ev) {
        const approvalUrl = ev.target.dataset.baseUrl;
        const hash = ev.target.dataset.hash;
        const xmlhttp = new XMLHttpRequest();
        xmlhttp.onload = function () {
            alert('Script approved');
        };
        xmlhttp.open('POST', approvalUrl + "/approveScriptHash");
        const data = new FormData();
        data.append('hash', hash);
        xmlhttp.setRequestHeader(crumb.fieldName, crumb.value);
        xmlhttp.send(data);
    }
});