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

import java.io.IOException;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AnnotatedWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.Whitelisted;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;

import groovy.lang.GroovyShell;

public class SandboxMethodContributorTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @TestExtension
    public static class TestBoxHelperContributor extends SandboxMethodContributor {
        @Override public Class<?>[] getContributedClasses() {
            return new Class<?>[] { BoxHelper.class };
        }
    }

    public static class BoxHelper {
        /** method call: {@code 'hello'.boxed()} */
        @Whitelisted
        public static String boxed(String s) {
            return "[" + s + "]";
        }

        /** property shorthand: {@code 'hello'.wrapped} (getter name: {@code getWrapped}) */
        @Whitelisted
        public static String getWrapped(String s) {
            return "{" + s + "}";
        }

        /** method with no {@code @Whitelisted}: must be rejected, not silently skipped */
        public static String secret(String s) {
            return "SECRET";
        }

        /** property getter with no {@code @Whitelisted}: property access must also be rejected */
        public static String getSecretProp(String s) {
            return "SECRET_PROP";
        }

        /** boolean property shorthand: {@code 'hello'.blank} (getter name: {@code isBlank}) */
        @Whitelisted
        public static boolean isBlank(String s) {
            return s.isEmpty();
        }

        /** boolean getter with no {@code @Whitelisted}: property access must be rejected */
        public static boolean isSecretFlag(String s) {
            return false;
        }

        /** whitelisted method that throws: exception must propagate unwrapped */
        @Whitelisted
        public static String failing(String s) {
            throw new IllegalStateException("boom");
        }
    }

    @Test public void contributedMethodCallAndPropertyAreReachable() throws Exception {
        assertEquals("[hello]", runInSandbox(new AnnotatedWhitelist(), "'hello'.boxed()"));
        assertEquals("{hello}", runInSandbox(new AnnotatedWhitelist(), "'hello'.wrapped"));
        assertEquals(false, runInSandbox(new AnnotatedWhitelist(), "'hello'.blank"));
    }

    @Test public void contributedMethodRejectedWhenNotWhitelisted() throws Exception {
        assertThrows(RejectedAccessException.class,
            () -> runInSandbox(new StaticWhitelist(), "'hello'.boxed()"));
        assertThrows(RejectedAccessException.class,
            () -> runInSandbox(new StaticWhitelist(), "'hello'.secret()"));
    }

    @Test public void contributedPropertyRejectedWhenNotWhitelisted() throws Exception {
        assertThrows(RejectedAccessException.class,
            () -> runInSandbox(new StaticWhitelist(), "'hello'.secretProp"));
        assertThrows(RejectedAccessException.class,
            () -> runInSandbox(new StaticWhitelist(), "'hello'.secretFlag"));
    }

    @Test public void contributedMethodExceptionPropagatesUnwrapped() throws Exception {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
            () -> runInSandbox(new AnnotatedWhitelist(), "'hello'.failing()"));
        assertEquals("boom", ex.getMessage());
    }

    private static Object runInSandbox(Whitelist whitelist, String script) {
        CompilerConfiguration cc = GroovySandbox.createSecureCompilerConfiguration();
        GroovyShell shell = new GroovyShell(cc);
        try {
            ProxyWhitelist wl = new ProxyWhitelist(whitelist,
                new StaticWhitelist("new groovy.lang.Script groovy.lang.Binding"));
            return new GroovySandbox().withWhitelist(wl).runScript(shell, script);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
