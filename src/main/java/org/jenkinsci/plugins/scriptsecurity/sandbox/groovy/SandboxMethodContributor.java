/*
 * The MIT License
 *
 * Copyright 2026 CloudBees, Inc.
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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import java.util.List;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.Whitelisted;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.Beta;

/**
 * Extension point for plugins to expose additional methods on existing types to sandboxed scripts,
 * using Groovy's extension method pattern.
 *
 * <p>A contributed class declares static methods whose first parameter is the receiver type.
 * Sandboxed scripts can then call those methods as if they were instance methods:
 *
 * <pre>{@code
 * // helper class contributed by a plugin:
 * public class MyHelpers {
 *     @Whitelisted
 *     public static String getLabel(Job job) { return job.getFullDisplayName(); }
 * }
 *
 * // in a sandboxed script:
 * echo job.getLabel()  // method call form
 * echo job.label       // property shorthand
 * }</pre>
 *
 * <p>{@link Whitelist#permitsStaticMethod} runs before every dispatch; a method must be annotated
 * {@link Whitelisted @Whitelisted} or have a {@code StaticWhitelist} entry, otherwise
 * {@link RejectedAccessException} is thrown.
 *
 * <p><b>Execution trust:</b> the whitelist check is an entrance gate only. Once permitted, the
 * contributed method body runs as trusted plugin code outside the sandbox; calls within it are
 * not subject to whitelist checks. Installed plugins are trusted by the admin.
 *
 */
@Restricted(Beta.class)
public abstract class SandboxMethodContributor implements ExtensionPoint {

    /**
     * Returns the static helper classes contributed by this extension.
     * Each class must declare static methods whose first parameter is the receiver type.
     * Methods callable from sandbox scripts must be annotated {@link Whitelisted @Whitelisted}.
     * Must not return {@code null} or contain {@code null} elements.
     */
    public abstract @NonNull Class<?>[] getContributedClasses();

    public static List<SandboxMethodContributor> all() {
        return ExtensionList.lookup(SandboxMethodContributor.class);
    }
}
