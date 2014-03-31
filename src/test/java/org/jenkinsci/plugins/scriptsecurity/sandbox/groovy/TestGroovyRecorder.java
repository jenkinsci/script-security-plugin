/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import groovy.lang.Binding;
import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Sample of integrating {@link SecureGroovyScript}.
 * The result of the configured Groovy script is set as the build description.
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public final class TestGroovyRecorder extends Recorder {

    private final SecureGroovyScript script;

    @DataBoundConstructor public TestGroovyRecorder(SecureGroovyScript script) {
        this.script = script.configuringWithKeyItem();
    }
    
    public SecureGroovyScript getScript() {
        return script;
    }
    
    @Override public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        try {
            Binding binding = new Binding();
            binding.setVariable("build", build);
            build.setDescription(script.evaluate(Jenkins.getInstance().getPluginManager().uberClassLoader, binding).toString());
        } catch (Exception x) {
            throw new IOException(x);
        }
        return true;
    }
    
    @Override public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    
    @Extension public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
        
        @Override public String getDisplayName() {
            return "Test Groovy Recorder";
        }

        @Override public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }
        
    }

}
