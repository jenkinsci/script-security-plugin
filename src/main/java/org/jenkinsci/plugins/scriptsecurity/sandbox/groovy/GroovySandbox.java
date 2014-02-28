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

import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import groovy.lang.GroovyShell;
import groovy.lang.Script;
import javax.annotation.Nonnull;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.kohsuke.groovy.sandbox.GroovyInterceptor;
import org.kohsuke.groovy.sandbox.SandboxTransformer;

/**
 * Allows Groovy scripts (including Groovy Templates) to be run inside a sandbox.
 */
public class GroovySandbox {

    /**
     * Prepares a compiler configuration the sandbox.
     * @return a compiler configuration set up to use the sandbox
     */
    public static @Nonnull CompilerConfiguration createSecureCompilerConfiguration() {
        CompilerConfiguration cc = new CompilerConfiguration();
        cc.addCompilationCustomizers(new SandboxTransformer());
        return cc;
    }
    
    /**
     * Runs a block such as {@link GroovyShell#evaluate(String)} in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
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
     * Runs a script in the sandbox.
     * You must have used {@link #createSecureCompilerConfiguration} to prepare the Groovy shell.
     * @param script a script ready to {@link Script#run}
     * @param whitelist the whitelist to use, such as {@link Whitelist#all()}
     * @throws RejectedAccessException in case an attempted call was not whitelisted
     */
    public static void runInSandbox(@Nonnull final Script script, @Nonnull Whitelist whitelist) throws RejectedAccessException {
        runInSandbox(new Runnable() {
            public void run() {
                script.run();
            }
        }, whitelist);
    }

    private GroovySandbox() {}

}
