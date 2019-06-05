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
import hudson.ExtensionList;
import hudson.model.RootAction;
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
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import org.codehaus.groovy.control.CompilationFailedException;
import org.codehaus.groovy.control.CompilationUnit;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.Phases;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
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
    
    private @CheckForNull Whitelist whitelist;
    private @CheckForNull ApprovalContext context;
    private @CheckForNull TaskListener listener;

    /**
     * Creates a sandbox with default settings.
     */
    public GroovySandbox() {}

    /**
     * Specify a whitelist.
     * By default {@link Whitelist#all} is used.
     * @return {@code this}
     */
    public GroovySandbox withWhitelist(@CheckForNull Whitelist whitelist) {
        this.whitelist = whitelist;
        return this;
    }

    /**
     * Specify an approval context.
     * By default {@link ApprovalContext#create} is used.
     * @return {@code this}
     */
    public GroovySandbox withApprovalContext(@CheckForNull ApprovalContext context) {
        this.context = context;
        return this;
    }

    /**
     * Specify a place to print messages.
     * By default nothing is printed.
     * @return {@code this}
     */
    public GroovySandbox withTaskListener(@CheckForNull TaskListener listener) {
        this.listener = listener;
        return this;
    }

    private @Nonnull Whitelist whitelist() {
        return whitelist != null ? whitelist : Whitelist.all();
    }

    /**
     * Starts a dynamic scope within which calls will be sandboxed.
     * @return a scope object, useful for putting this into a {@code try}-with-resources block
     */
    @SuppressWarnings("deprecation") // internal use of accessRejected still valid
    public Scope enter() {
        GroovyInterceptor sandbox = new SandboxInterceptor(whitelist());
        ApprovalContext _context = context != null ? context : ApprovalContext.create();
        sandbox.register();
        ScriptApproval.pushRegistrationCallback(x -> {
            if (ExtensionList.lookup(RootAction.class).get(ScriptApproval.class) == null) {
                return; // running in unit test, ignore
            }
            String signature = x.getSignature();
            if (!StaticWhitelist.isPermanentlyBlacklisted(signature)) {
                ScriptApproval.get().accessRejected(x, _context);
            }
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
     * Compiles and runs a script within the sandbox.
     * @param shell the shell to be used; see {@link #createSecureCompilerConfiguration} and similar methods
     * @param script the script to run
     * @return the return value of the script
     */
    public Object runScript(@Nonnull GroovyShell shell, @Nonnull String script) {
        GroovySandbox derived = new GroovySandbox().
            withApprovalContext(context).
            withTaskListener(listener).
            withWhitelist(new ProxyWhitelist(new ClassLoaderWhitelist(shell.getClassLoader()), whitelist()));
        try (Scope scope = derived.enter()) {
            return shell.parse(script).run();
        }
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
     * @deprecated use {@link #enter}
     */
    @Deprecated
    public static void runInSandbox(@Nonnull Runnable r, @Nonnull Whitelist whitelist) throws RejectedAccessException {
        try (Scope scope = new GroovySandbox().withWhitelist(whitelist).enter()) {
            r.run();
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
     * @deprecated use {@link #enter}
     */
    @Deprecated
    public static <V> V runInSandbox(@Nonnull Callable<V> c, @Nonnull Whitelist whitelist) throws Exception {
        try (Scope scope = new GroovySandbox().withWhitelist(whitelist).enter()) {
            return c.call();
        }
    }

    /**
     * @deprecated Use {@link #runScript}.
     */
    @Deprecated
    public static void runInSandbox(@Nonnull final Script script, @Nonnull Whitelist whitelist) throws RejectedAccessException {
        runInSandbox((Runnable) script.run(), whitelist);
    }

    /**
     * Runs a script in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
     * @param script a script ready to {@link Script#run}, created for example by {@link GroovyShell#parse(String)}
     * @param whitelist the whitelist to use, such as {@link Whitelist#all()}
     * @return the value produced by the script, if any
     * @throws RejectedAccessException in case an attempted call was not whitelisted
     * @deprecated insecure; use {@link #run(GroovyShell, String, Whitelist)} or {@link #runScript}
     */
    @Deprecated
    public static Object run(@Nonnull Script script, @Nonnull final Whitelist whitelist) throws RejectedAccessException {
        LOGGER.log(Level.WARNING, null, new IllegalStateException(Messages.GroovySandbox_useOfInsecureRunOverload()));
        Whitelist wrapperWhitelist = new ProxyWhitelist(
                new ClassLoaderWhitelist(script.getClass().getClassLoader()),
                whitelist);
        try (Scope scope = new GroovySandbox().withWhitelist(wrapperWhitelist).enter()) {
            return script.run();
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
     * @deprecated use {@link #runScript}
     */
    @Deprecated
    public static Object run(@Nonnull final GroovyShell shell, @Nonnull final String script, @Nonnull final Whitelist whitelist) throws RejectedAccessException {
        return new GroovySandbox().withWhitelist(whitelist).runScript(shell, script);
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
