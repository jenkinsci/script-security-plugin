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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.io.Serializable;

import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Items;
import hudson.util.FormValidation;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A classpath entry used for a script.
 */
public final class ClasspathEntry extends AbstractDescribableImpl<ClasspathEntry> implements Serializable {

    private static final long serialVersionUID = -2873408550951192200L;
    private final @NonNull URL url;
    private transient String oldPath;
    private transient boolean shouldBeApproved;

    @SuppressFBWarnings(value = {"SE_TRANSIENT_FIELD_NOT_RESTORED"}, justification = "Null is the expected value for deserealized instances of this class")
    @DataBoundConstructor
    public ClasspathEntry(@NonNull String path) throws MalformedURLException {
        url = pathToURL(path);
    }
    
    static URL pathToURL(String path) throws MalformedURLException {
        if (path.isEmpty()) {
            throw new MalformedURLException("JENKINS-37599: empty classpath entries not allowed");
        }
        try {
            return new URL(path);
        } catch (MalformedURLException x) {
            File f = new File(path);
            if (f.isAbsolute()) {
                return f.toURI().toURL();
            } else {
                throw new MalformedURLException("Classpath entry ‘" + path + "’ does not look like either a URL or an absolute file path");
            }
        }
    }

    /** Returns {@code null} if another protocol or unable to perform the conversion. */
    private static File urlToFile(@NonNull URL url) {
        if (url.getProtocol().equals("file")) {
            try {
                return new File(url.toURI());
            } catch (URISyntaxException x) {
                // ?
            }
        }
        return null;
    }

    static String urlToPath(URL url) {
        final File file = urlToFile(url);
        return file != null ? file.getAbsolutePath() : url.toString();
    }

    /**
     * Checks whether an URL would be considered a class directory by {@link java.net.URLClassLoader}.
     * According to its <a href="http://docs.oracle.com/javase/6/docs/api/java/net/URLClassLoader.html"specification</a>
     * an URL will be considered an class directory if it ends with /.
     * In the case the URL uses a {@code file:} protocol a check is performed to see if it is a directory as an additional guard
     * in case a different class loader is used by other {@link Language} implementation.
     */
    static boolean isClassDirectoryURL(@NonNull URL url) {
        final File file = urlToFile(url);
        if (file != null && file.isDirectory()) {
            return true;
            // If the URL is a file but does not exist we fallback to default behaviour
            // as non existence will be dealt with when trying to use it.
        }
        String u = url.toExternalForm();
        return u.endsWith("/") && !u.startsWith("jar:");
    }

    /**
     * Checks whether the entry would be considered a class directory.
     * @see #isClassDirectoryURL(URL)
     */
    public boolean isClassDirectory() {
        return isClassDirectoryURL(url);
    }
    
    public @NonNull String getPath() {
        return urlToPath(url);
    }

    public @NonNull URL getURL() {
        return url;
    }

    private @CheckForNull URI getURI() {
        try {
            return url.toURI();
        } catch(URISyntaxException ex) {
            return null;
        }
    }

    @Restricted(NoExternalUse.class) // for jelly view
    public String getOldPath() {
        return oldPath;
    }

    @DataBoundSetter
    public void setOldPath(String oldPath) {
        this.oldPath = oldPath;
    }

    public boolean isShouldBeApproved() {
        return shouldBeApproved;
    }

    @DataBoundSetter
    public void setShouldBeApproved(boolean shouldBeApproved) {
        this.shouldBeApproved = shouldBeApproved;
    }

    @Restricted(NoExternalUse.class) // for jelly view
    public boolean isScriptAutoApprovalEnabled() {
        return ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED;
    }

    @Restricted(NoExternalUse.class) // for jelly view
    public boolean isEntryApproved() {
        return ScriptApproval.get().isClasspathEntryApproved(url);
    }

    @Override
    public String toString() {
        return url.toString();
    }
    
    @Override
    @SuppressFBWarnings(value = "DMI_BLOCKING_METHODS_ON_URL", 
            justification = "Method call has been optimized, but we still need URLs as a fallback") 
    public boolean equals(Object obj) {
        if (!(obj instanceof ClasspathEntry)) {
            return false;
        }
        // Performance optimization to avoid domain name resolution
        final ClasspathEntry cmp = (ClasspathEntry)obj; 
        final URI uri = getURI();
        return uri != null ? uri.equals(cmp.getURI()) : url.equals(cmp.url);
    }

    @SuppressFBWarnings(value = "DMI_BLOCKING_METHODS_ON_URL", 
            justification = "Method call has been optimized, but we still need URLs as a fallback") 
    @Override public int hashCode() {
        // Performance optimization to avoid domain name resolution
        final URI uri = getURI();
        return uri != null ? uri.hashCode() : url.hashCode();
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<ClasspathEntry> {
        @NonNull
        @Override
        public String getDisplayName() {
            return "ClasspathEntry";
        }
        
        public FormValidation doCheckPath(@QueryParameter String value, @QueryParameter String oldPath, @QueryParameter boolean shouldBeApproved) {
            if(!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(value)) {
                return FormValidation.warning("Enter a file path or URL."); // TODO I18N
            }
            try {
                ClasspathEntry entry = new ClasspathEntry(value);
                entry.setShouldBeApproved(shouldBeApproved);
                entry.setOldPath(oldPath);
                return ScriptApproval.get().checking(entry);
            } catch (MalformedURLException x) {
                return FormValidation.error(x, "Could not parse: " + value); // TODO I18N
            }
        }
    }

    @Initializer(before=InitMilestone.EXTENSIONS_AUGMENTED) public static void alias() {
        Items.XSTREAM2.alias("entry", ClasspathEntry.class);
    }

}
