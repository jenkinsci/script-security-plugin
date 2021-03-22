(function() {
    function toggleTargetDisplay(element, isShowDesired) {
        var parentToggle = element.parentElement;
        var targetId = parentToggle.getAttribute('data-expand-target-id');
        var isCodeMirror = 'true' === parentToggle.getAttribute('data-expand-codemirror');
        var isAsyncCodeMirror = 'true' === parentToggle.getAttribute('data-expand-async-codemirror');
        var target = document.getElementById(targetId);
        if (!target) {
            console.warn('No target found for id', targetId);
        }
        
        var showButton = parentToggle.querySelector('.js-toggle-show-icon');
        var hideButton = parentToggle.querySelector('.js-toggle-hide-icon');
        if (isShowDesired) {
            target.classList.remove('hidden-element');
            showButton.classList.add('hidden-element');
            hideButton.classList.remove('hidden-element');
        } else {
            target.classList.add('hidden-element');
            hideButton.classList.add('hidden-element');
            showButton.classList.remove('hidden-element');
        }
        
        if (isCodeMirror) {
            var textArea = target.querySelector('textarea');
            var cm = textArea.codemirrorObject;
            if (cm) {
                // checking existence first for languages not supported by CodeMirror (like System Commands)
                // refresh prevents a buggy scrollbar appearance due to dynamical render
                cm.refresh();
            }
        } else if (isShowDesired && isAsyncCodeMirror) {
            var asyncUrl = parentToggle.getAttribute('data-expand-url');

            var loadingElement = target.querySelector('.js-expand-async-loading');
            var errorElementOther = target.querySelector('.js-expand-async-error');
            var errorElement403 = target.querySelector('.js-expand-async-error-403');
            // reset status first
            if (loadingElement) {
                loadingElement.classList.remove('hidden-element');
            }
            if (errorElementOther) {
                errorElementOther.classList.add('hidden-element');
            }
            if (errorElement403) {
                errorElement403.classList.add('hidden-element');
            }

            // no need to re-load the script the next time
            parentToggle.setAttribute('data-expand-async-codemirror', 'already-loaded');

            new Ajax.Request(asyncUrl, {
                contentType:"application/json",
                encoding:"UTF-8",
                onSuccess: function(rsp) {
                    if (loadingElement) {
                        loadingElement.classList.add('hidden-element');
                    }
                    
                    var scriptContent = rsp.responseText;
                    
                    // scriptContent is escaped inside _scriptContent.jelly
                    target.innerHTML = scriptContent;
                    
                    // from hudson-behavior.js
                    evalInnerHtmlScripts(scriptContent, function() {
                        Behaviour.applySubtree(target);
                        var textArea = target.querySelector('textarea');
                        var cm = textArea.codemirrorObject;
                        if (cm) {
                            // checking existence first for languages not supported by CodeMirror (like System Commands)
                            // refresh prevents a buggy scrollbar appearance due to dynamical render 
                            cm.refresh();
                        }
                        // next expansion the code has to be refreshed
                        parentToggle.setAttribute('data-expand-codemirror', 'true');
                    });
                },
                onFailure: function(response) {
                    if (loadingElement) {
                        loadingElement.classList.add('hidden-element');
                    }
                    if (response.status === 403) {
                        // most likely to be a CSRF issue due to disconnection
                        if (errorElement403) {
                            errorElement403.classList.remove('hidden-element');
                        }
                    } else {
                        // 404 or otherthing, generic message
                        if (errorElementOther) {
                            errorElementOther.classList.remove('hidden-element');
                        }
                    }
                }
            });
        }
    }

    Behaviour.specify(".js-toggle-show-icon", "show-icon", 0, function(element) {
        element.observe('click', function() {
            toggleTargetDisplay(element, true);
        });
    });

    Behaviour.specify(".js-toggle-hide-icon", "hide-icon", 0, function(element) {
        element.observe('click', function() {
            toggleTargetDisplay(element, false);
        });
    });

    // the priority ensures it's executed after "TEXTAREA.codemirror" 
    Behaviour.specify(".js-async-hidden-element", "replace-js-async", /* priority */ 1, function(element) {
        element.classList.add('hidden-element');
        element.classList.remove('js-async-hidden-element');
    });

    Behaviour.specify("table tr.js-selectable-row", "click-to-select", 0, function(row) {
        row.observe('click', onLineClicked);
    });

    Behaviour.specify("table tr.js-selectable-row input[type='checkbox']", "click-to-select", 0, function(checkbox) {
        checkbox.observe('change', function() { onCheckChanged(this) });
    });

    function onLineClicked(event){
        var line = this;
        // to allow click on checkbox or on label to act normally
        var targetBypassClick = event.target && event.target.classList.contains('js-bypass-click');
        if (targetBypassClick) {
            return;
        }
        
        var checkbox = line.querySelector('input[type="checkbox"]');
        checkbox.checked = !checkbox.checked;
        onCheckChanged(checkbox);
    }

    function onCheckChanged(checkBox){
        // up is a prototype helper method 
        var line = checkBox.up('tr');
        if (checkBox.checked) {
            line.addClassName('selected');
        } else {
            line.removeClassName('selected');
        }
    }

    // ######### For fullScript_pending.jelly #########

    Behaviour.specify(".js-button-pending-approve-all", "approved-approve-all", 0, function(element) {
        element.observe('click', handleClickToProcessAction);
    });

    Behaviour.specify(".js-button-pending-deny-all", "approved-deny-all", 0, function(element) {
        element.observe('click', handleClickToProcessAction);
    });

    // ######### For fullScript_approved.jelly #########

    Behaviour.specify(".js-button-approved-revoke-all", "approved-revoke-all", 0, function(element) {
        element.observe('click', handleClickToProcessAction);
    });
    
    function handleClickToProcessAction() {
        var element = this;
        var containerId = element.getAttribute('data-container-id');
        var actionUrl = element.getAttribute('data-action-url');
        var confirmMessage = element.getAttribute('data-action-confirm-message');

        processAction(containerId, actionUrl, confirmMessage);
    }

    function processAction(containerId, actionUrl, confirmMessage) {
        var container = document.getElementById(containerId);
        var allCheckboxes = container.querySelectorAll('input[type="checkbox"].js-checkbox-hash');
        var checkedHashes = [];
        allCheckboxes.forEach(function(c){
            if (c.checked) {
                var hash = c.getAttribute('data-hash');
                checkedHashes.push(hash);
            }
        });

        var errorPanel = container.querySelector('.js-error-no-selected');
        if (checkedHashes.length === 0) {
            if (errorPanel) {
                errorPanel.classList.remove('hidden-element');
            } else {
                console.warn('There is no selected item, cannot proceed with the action.');
            }
            return;
        } else {
            if (errorPanel) {
                errorPanel.classList.add('hidden-element');
            }
        }

        if (confirmMessage) {
            var wasConfirmed = confirm(confirmMessage);
            if (!wasConfirmed) {
                return;
            }
        }

        var params = {hashes: checkedHashes};
        new Ajax.Request(actionUrl, {
            postBody: Object.toJSON(params),
            contentType:"application/json",
            encoding:"UTF-8",
            onComplete: function(rsp) {
                window.location.reload();
            }
        });
    }
})();