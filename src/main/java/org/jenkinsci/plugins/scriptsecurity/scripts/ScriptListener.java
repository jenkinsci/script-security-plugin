package org.jenkinsci.plugins.scriptsecurity.scripts;

import hudson.ExtensionPoint;
import hudson.model.Run;
import jenkins.util.Listeners;

/**
 * A listener to track usage of Groovy scripts running outside of a sandbox.
 *
 * @see org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript#evaluate(ClassLoader, groovy.lang.Binding, hudson.model.TaskListener)
 */
public interface ScriptListener extends ExtensionPoint {

    /**
     * Called when a groovy script is executed in a pipeline outside of a sandbox.
     *
     * @see org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript#evaluate(ClassLoader, groovy.lang.Binding, hudson.model.TaskListener)
     * @param script The Groovy script that is executed.
     * @param origin A descriptive, trackable identifier of the entity running the script.
     */
    void onScript(String script, String origin);

    /**
     * Fires the {@link #onScript(String, String)} event to track the usage of groovy scripts running outside the sandbox.
     *
     * @see org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript#evaluate(ClassLoader, groovy.lang.Binding, hudson.model.TaskListener)
     * @param script The Groovy script that is excecuted.
     * @param origin A descriptive, trackable identifier of the entity running the script.
     */
    static void fireScriptEvent(String script, String origin) {
        Listeners.notify(ScriptListener.class, true, listener -> listener.onScript(script, origin));
    }
}
