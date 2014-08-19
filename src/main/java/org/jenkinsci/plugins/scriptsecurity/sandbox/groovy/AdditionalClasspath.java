/*
 * The MIT License
 * 
 * Copyright (c) 2014 IKEDA Yasuyuki
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

import java.io.File;
import java.io.IOException;

import jenkins.model.Jenkins;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

/**
 * A classpath used for a groovy script.
 */
public class AdditionalClasspath extends AbstractDescribableImpl<AdditionalClasspath> {
    private final String path;
    
    @DataBoundConstructor
    public AdditionalClasspath(String path) {
        this.path = StringUtils.trim(path);
    }
    
    public String getPath() {
        return path;
    }
    
    @Override
    public String toString() {
        return String.format("Classpath: %s", getPath());
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AdditionalClasspath)) {
            return false;
        }
        
        if (getPath() == null) {
            return ((AdditionalClasspath)obj).getPath() == null;
        }
        
        return getPath().equals(((AdditionalClasspath)obj).getPath());
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<AdditionalClasspath> {
        @Override
        public String getDisplayName() {
            return "AdditionalClasspath";
        }
        
        public FormValidation doCheckPath(@QueryParameter String path) {
            if (StringUtils.isBlank(path)) {
                return FormValidation.ok();
            }
            File file = new File(path);
            if (!file.isAbsolute()) {
                return FormValidation.error(Messages.AdditionalClasspath_path_notAbsolute());
            }
            if (!file.exists()) {
                return FormValidation.error(Messages.AdditionalClasspath_path_notExists());
            }
            if (Jenkins.getInstance().isUseSecurity() && !Jenkins.getInstance().hasPermission(Jenkins.RUN_SCRIPTS)) {
                try {
                    if (!ScriptApproval.get().isClasspathApproved(path)) {
                        return FormValidation.error(Messages.AdditionalClasspath_path_notApproved());
                    }
                } catch(IOException e) {
                    return FormValidation.error(Messages.AdditionalClasspath_path_notApproved(), e);
                }
            }
            return FormValidation.ok();
        }
    }
}
