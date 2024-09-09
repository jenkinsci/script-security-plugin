// https://issues.jenkins-ci.org/browse/JENKINS-15604 workaround:
function cmChange(editor, change) {
    editor.save();
    document.querySelectorAll('.validated').forEach(function (e) {e.onchange();});
}
