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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import javax.annotation.CheckForNull;
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

    /** Returns {@code null} if another protocol or unable to perform the conversion. */
    private static File urlToFile(@Nonnull URL url) {
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
    static boolean isClassDirectoryURL(@Nonnull URL url) {
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
    
    public @Nonnull String getPath() {
        return urlToPath(url);
    }

    public @Nonnull URL getURL() {
        return url;
    }

    private @CheckForNull URI getURI() {
        try {
            return url.toURI();
        } catch(URISyntaxException ex) {
            return null;
        }
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
        @Override
        public String getDisplayName() {
            return "ClasspathEntry";
        }
        
        public FormValidation doCheckPath(@QueryParameter String value) {
            if (StringUtils.isBlank(value)) {
                return FormValidation.warning("Enter a file path or URL."); // TODO I18N
            }
            try {
                return ScriptApproval.get().checking(new ClasspathEntry(value));
            } catch (MalformedURLException x) {
                return FormValidation.error(x, "Could not parse: " + value); // TODO I18N
            }
        }
    }

    @Initializer(before=InitMilestone.EXTENSIONS_AUGMENTED) public static void alias() {
        Items.XSTREAM2.alias("entry", ClasspathEntry.class);
    }

}
