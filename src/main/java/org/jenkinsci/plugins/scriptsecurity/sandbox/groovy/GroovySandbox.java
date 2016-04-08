/*
 * The MIT License
 *
 * Copyright 2014 CloudBees, Inc.
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.GroovyShell;
import groovy.lang.Script;

import java.util.concurrent.Callable;
import javax.annotation.Nonnull;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;
import org.kohsuke.groovy.sandbox.GroovyInterceptor;
import org.kohsuke.groovy.sandbox.SandboxTransformer;

/**
 * Allows Groovy scripts (including Groovy Templates) to be run inside a sandbox.
 */
public class GroovySandbox {

    /**
     * Prepares a compiler configuration the sandbox.
     *
     * <h2>CAUTION</h2>
     * <p>
     * When creating {@link GroovyShell} with this {@link CompilerConfiguration},
     * you also have to use {@link #createSecureClassLoader(ClassLoader)} to wrap
     * a classloader of your choice into sandbox-aware one.
     *
     * <p>
     * Otherwise the classloader that you provide to {@link GroovyShell} might
     * have its own copy of groovy-sandbox, which lets the code escape the sandbox.
     *
     * @return a compiler configuration set up to use the sandbox
     */
    public static @Nonnull CompilerConfiguration createSecureCompilerConfiguration() {
        CompilerConfiguration cc = new CompilerConfiguration();
        cc.addCompilationCustomizers(new SandboxTransformer());
        return cc;
    }

    /**
     * Prepares a classloader for Groovy shell for sandboxing.
     *
     * See {@link #createSecureCompilerConfiguration()} for the discussion.
     */
    @SuppressFBWarnings(value = "DP_CREATE_CLASSLOADER_INSIDE_DO_PRIVILEGED", justification = "Should be managed by the caller.")
    public static @Nonnull ClassLoader createSecureClassLoader(ClassLoader base) {
        return new SandboxResolvingClassLoader(base);
    }
    
    /**
     * Runs a block in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
     * Use {@link #run} instead whenever possible.
     * @param r a block of code during whose execution all calls are intercepted
     * @param whitelist the whitelist to use, such as {@link Whitelist#all()}
     * @throws RejectedAccessException in case an attempted call was not whitelisted
     */
    public static void runInSandbox(@Nonnull Runnable r, @Nonnull Whitelist whitelist) throws RejectedAccessException {
        GroovyInterceptor sandbox = new SandboxInterceptor(whitelist);
        sandbox.register();
        try {
            r.run();
        } finally {
            sandbox.unregister();
        }
    }

    /**
     * Runs a function in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
     * Use {@link #run} instead whenever possible.
     * @param c a block of code during whose execution all calls are intercepted
     * @param whitelist the whitelist to use, such as {@link Whitelist#all()}
     * @return the return value of the block
     * @throws RejectedAccessException in case an attempted call was not whitelisted
     * @throws Exception in case the block threw some other exception
     */
    public static <V> V runInSandbox(@Nonnull Callable<V> c, @Nonnull Whitelist whitelist) throws Exception {
        GroovyInterceptor sandbox = new SandboxInterceptor(whitelist);
        sandbox.register();
        try {
            return c.call();
        } finally {
            sandbox.unregister();
        }
    }

    /**
     * @deprecated Use {@link #run} to ensure that methods defined inside the script do not need to be whitelisted.
     */
    @Deprecated
    public static void runInSandbox(@Nonnull final Script script, @Nonnull Whitelist whitelist) throws RejectedAccessException {
        runInSandbox(new Runnable() {
            public void run() {
                script.run();
            }
        }, whitelist);
    }

    /**
     * Runs a script in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
     * @param script a script ready to {@link Script#run}, created for example by {@link GroovyShell#parse(String)}
     * @param whitelist the whitelist to use, such as {@link Whitelist#all()}
     * @return the value produced by the script, if any
     * @throws RejectedAccessException in case an attempted call was not whitelisted
     */
    public static Object run(@Nonnull Script script, @Nonnull final Whitelist whitelist) throws RejectedAccessException {
        Whitelist wrapperWhitelist = new ProxyWhitelist(
                new ClassLoaderWhitelist(script.getClass().getClassLoader()),
                whitelist);
        GroovyInterceptor sandbox = new SandboxInterceptor(wrapperWhitelist);
        sandbox.register();
        try {
            return script.run();
        } finally {
            sandbox.unregister();
        }
    }

    private GroovySandbox() {}

}
