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

package org.jenkinsci.plugins.scriptsecurity.scripts;

import java.io.File;
import java.io.IOException;

import jenkins.model.Jenkins;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.Util;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Items;
import hudson.util.FormValidation;
import javax.annotation.Nonnull;

/**
 * A classpath entry used for a script.
 */
public final class ClasspathEntry extends AbstractDescribableImpl<ClasspathEntry> {

    private final @Nonnull String path;
    
    @DataBoundConstructor
    public ClasspathEntry(@Nonnull String path) {
        this.path = Util.fixNull(path);
    }
    
    public @Nonnull String getPath() {
        return path;
    }
    
    @Override
    public String toString() {
        return path;
    }
    
    @Override
    public boolean equals(Object obj) {
        return obj instanceof ClasspathEntry && ((ClasspathEntry) obj).path.equals(path);
    }

    @Override public int hashCode() {
        return path.hashCode();
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<ClasspathEntry> {
        @Override
        public String getDisplayName() {
            return "ClasspathEntry";
        }
        
        public FormValidation doCheckPath(@QueryParameter String path) {
            if (StringUtils.isBlank(path)) {
                return FormValidation.ok();
            }
            File file = new File(path);
            if (!file.isAbsolute()) {
                return FormValidation.error(Messages.ClasspathEntry_path_notAbsolute());
            }
            if (!file.exists()) {
                return FormValidation.error(Messages.ClasspathEntry_path_notExists());
            }
            if (Jenkins.getInstance().isUseSecurity() && !Jenkins.getInstance().hasPermission(Jenkins.RUN_SCRIPTS)) {
                try {
                    if (!ScriptApproval.get().isClasspathApproved(path)) {
                        return FormValidation.error(Messages.ClasspathEntry_path_notApproved());
                    }
                } catch(IOException e) {
                    return FormValidation.error(Messages.ClasspathEntry_path_notApproved(), e);
                }
            }
            return FormValidation.ok();
        }
    }

    @Initializer(before=InitMilestone.EXTENSIONS_AUGMENTED) public static void alias() {
        Items.XSTREAM2.alias("entry", ClasspathEntry.class);
    }

}
