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
import groovy.grape.GrabAnnotationTransformation;
import groovy.lang.GroovyClassLoader;
import groovy.lang.GroovyShell;
import static groovy.lang.GroovyShell.DEFAULT_CODE_BASE;
import groovy.lang.Script;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.CodeSource;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import org.codehaus.groovy.control.CompilationFailedException;
import org.codehaus.groovy.control.CompilationUnit;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.Phases;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;
import org.jenkinsci.plugins.scriptsecurity.scripts.ApprovalContext;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApprovalNote;
import org.kohsuke.groovy.sandbox.GroovyInterceptor;
import org.kohsuke.groovy.sandbox.SandboxTransformer;

/**
 * Allows Groovy scripts (including Groovy Templates) to be run inside a sandbox.
 */
public final class GroovySandbox {

    public static final Logger LOGGER = Logger.getLogger(GroovySandbox.class.getName());
    
    private Whitelist whitelist;
    private ApprovalContext context;
    private TaskListener listener;

    /**
     * TODO
     */
    public GroovySandbox() {}

    /**
     * TODO
     * @return {@code this}
     */
    public GroovySandbox withWhitelist(@Nonnull Whitelist whitelist) {
        this.whitelist = whitelist;
        return this;
    }

    /**
     * TODO
     * @return {@code this}
     */
    public GroovySandbox withApprovalContext(@Nonnull ApprovalContext context) {
        this.context = context;
        return this;
    }

    /**
     * TODO
     * @return {@code this}
     */
    public GroovySandbox withTaskListener(@Nonnull TaskListener listener) {
        this.listener = listener;
        return this;
    }

    /**
     * TODO
     * @return a scope object, useful for putting this into a {@code try}-with-resources block
     */
    @SuppressWarnings("deprecation") // internal use of accessRejected still valid
    public Scope enter() {
        GroovyInterceptor sandbox = new SandboxInterceptor(whitelist != null ? whitelist : Whitelist.all());
        ApprovalContext _context = context != null ? context : ApprovalContext.create();
        sandbox.register();
        ScriptApproval.pushRegistrationCallback(x -> {
            ScriptApproval.get().accessRejected(x, _context);
            if (listener != null) {
                ScriptApprovalNote.print(listener, x);
            }
        });
        return () -> {
            sandbox.unregister();
            ScriptApproval.popRegistrationCallback();
        };
    }

    /**
     * Handle for exiting the dynamic scope of the Groovy sandbox.
     * @see #enter
     */
    @FunctionalInterface
    public interface Scope extends AutoCloseable {

        @Override void close();

    }

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
        CompilerConfiguration cc = createBaseCompilerConfiguration();
        cc.addCompilationCustomizers(new SandboxTransformer());
        return cc;
    }

    /**
     * Prepares a compiler configuration that rejects certain AST transformations. Used by {@link #createSecureCompilerConfiguration()}.
     */
    public static @Nonnull CompilerConfiguration createBaseCompilerConfiguration() {
        CompilerConfiguration cc = new CompilerConfiguration();
        cc.addCompilationCustomizers(new RejectASTTransformsCustomizer());
        cc.setDisabledGlobalASTTransformations(new HashSet<>(Collections.singletonList(GrabAnnotationTransformation.class.getName())));
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
    // TODO deprecated use #enter
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
    // TODO deprecated use #enter
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
     * @deprecated insecure; use {@link #run(GroovyShell, String, Whitelist)} instead
     */
    @Deprecated
    public static Object run(@Nonnull Script script, @Nonnull final Whitelist whitelist) throws RejectedAccessException {
        LOGGER.log(Level.WARNING, null, new IllegalStateException(Messages.GroovySandbox_useOfInsecureRunOverload()));
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

    /**
     * Runs a script in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
     * @param shell a shell ready for {@link GroovyShell#parse(String)}
     * @param script a script
     * @param whitelist the whitelist to use, such as {@link Whitelist#all()}
     * @return the value produced by the script, if any
     * @throws RejectedAccessException in case an attempted call was not whitelisted
     */
    // TODO deprecated use #GroovySandbox with some new method TBD
    public static Object run(@Nonnull final GroovyShell shell, @Nonnull final String script, @Nonnull final Whitelist whitelist) throws RejectedAccessException {
        try {
            final Script s = runInSandbox(new Callable<Script>() {
                @Override
                public Script call() throws Exception {
                    return shell.parse(script);
                }
            }, whitelist);
            return runInSandbox(new Callable<Object>() {
                @Override
                public Object call() throws Exception {
                    return s.run();
                }
            }, new ProxyWhitelist(new ClassLoaderWhitelist(s.getClass().getClassLoader()), whitelist));
        } catch (RuntimeException x) { // incl. RejectedAccessException
            throw x;
        } catch (Exception x) {
            throw new AssertionError(x);
        }
    }

    /**
     * Checks a script for compilation errors in a sandboxed environment, without going all the way to actual class
     * creation or initialization.
     * @param script The script to check
     * @param classLoader The {@link GroovyClassLoader} to use during compilation.
     * @return The {@link FormValidation} for the compilation check.
     */
    public static @Nonnull FormValidation checkScriptForCompilationErrors(String script, GroovyClassLoader classLoader) {
        try {
            CompilationUnit cu = new CompilationUnit(
                    createSecureCompilerConfiguration(),
                    new CodeSource(new URL("file", "", DEFAULT_CODE_BASE), (Certificate[]) null),
                    classLoader);
            cu.addSource("Script1", script);
            cu.compile(Phases.CANONICALIZATION);
        } catch (MalformedURLException | CompilationFailedException e) {
            return FormValidation.error(e.getLocalizedMessage());
        }

        return FormValidation.ok();
    }

}
