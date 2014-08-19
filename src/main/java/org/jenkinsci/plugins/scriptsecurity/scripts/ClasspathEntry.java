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
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Items;
import hudson.util.FormValidation;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import javax.annotation.Nonnull;

/**
 * A classpath entry used for a script.
 */
public final class ClasspathEntry extends AbstractDescribableImpl<ClasspathEntry> {

    private final @Nonnull URL url;
    
    @DataBoundConstructor
    public ClasspathEntry(@Nonnull String path) throws MalformedURLException {
        url = pathToURL(path);
    }
    
    static URL pathToURL(String path) throws MalformedURLException {
        try {
            return new URL(path);
        } catch (MalformedURLException x) {
            return new File(path).toURI().toURL();
        }
    }

    static String urlToPath(URL url) {
        if (url.getProtocol().equals("file")) {
            try {
                return new File(url.toURI()).getAbsolutePath();
            } catch (URISyntaxException x) {
                // ?
            }
        }
        return url.toString();
    }
    
    public @Nonnull String getPath() {
        return urlToPath(url);
    }

    public @Nonnull URL getURL() {
        return url;
    }
    
    @Override
    public String toString() {
        return url.toString();
    }
    
    @Override
    public boolean equals(Object obj) {
        return obj instanceof ClasspathEntry && ((ClasspathEntry) obj).url.equals(url);
    }

    @Override public int hashCode() {
        return url.hashCode();
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<ClasspathEntry> {
        @Override
        public String getDisplayName() {
            return "ClasspathEntry";
        }
        
        public FormValidation doCheckPath(@QueryParameter String value) {
            if (StringUtils.isBlank(value)) {
                return FormValidation.warning("Enter a file path or URL."); // TODO I18N
            }
            URL url;
            try {
                url = pathToURL(value);
            } catch (MalformedURLException x) {
                return FormValidation.error(x, "Could not parse: " + value); // TODO I18N
            }
            try {
                url.openStream().close();
            } catch (FileNotFoundException x) {
                return FormValidation.error(Messages.ClasspathEntry_path_notExists());
            } catch (IOException x) {
                return FormValidation.error(x, "Could not verify: " + url); // TODO I18N
            }
            if (Jenkins.getInstance().isUseSecurity() && !Jenkins.getInstance().hasPermission(Jenkins.RUN_SCRIPTS)) {
                try {
                    if (!ScriptApproval.get().isClasspathApproved(url)) {
                        return FormValidation.error(Messages.ClasspathEntry_path_notApproved());
                    }
                } catch(IOException e) {
                    return FormValidation.error(e, Messages.ClasspathEntry_path_notApproved());
                }
            }
            return FormValidation.ok();
        }
    }

    @Initializer(before=InitMilestone.EXTENSIONS_AUGMENTED) public static void alias() {
        Items.XSTREAM2.alias("entry", ClasspathEntry.class);
    }

}
