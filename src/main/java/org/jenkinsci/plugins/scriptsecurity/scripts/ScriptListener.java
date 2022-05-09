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
     * @param script The Groovy script that is excecuted.
     * @param run The run calling the Groovy script.
     */
    void onScriptFromPipeline(String script, Run run);

    /**
     * Fires the {@link #onScriptFromPipeline(String, Run)} event to track the usage of the script console.
     *
     * @see org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript#evaluate(ClassLoader, groovy.lang.Binding, hudson.model.TaskListener)
     * @param script The Groovy script that is excecuted.
     * @param run The run calling the Groovy script.
     */
    static void fireScriptFromPipelineEvent(String script, Run run) {
        Listeners.notify(ScriptListener.class, true, listener -> listener.onScriptFromPipeline(script, run));
    }
}
