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

import groovy.lang.GString;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.GenericWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import groovy.lang.GroovyShell;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AnnotatedWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.Whitelisted;
import org.junit.Test;
import static org.junit.Assert.*;

public class SandboxInterceptorTest {

    @Test public void genericWhitelist() throws Exception {
        assertEvaluate(new GenericWhitelist(), 3, "'foo bar baz'.split(' ').length");
        assertEvaluate(new GenericWhitelist(), false, "def x = null; x != null");
    }

    /** Checks that {@link GString} is handled sanely. */
    @Test public void testGString() throws Exception {
        assertEvaluate(new AnnotatedWhitelist(), "-foo1", "def x = 1; new " + Clazz.class.getName() + "().method(\"foo${x}\")");
    }

    public static final class Clazz {
        @Whitelisted public Clazz() {}
        @Whitelisted public String method(String x) {return "-" + x;}
    }

    private static void assertEvaluate(Whitelist whitelist, final Object expected, final String script) {
        final GroovyShell shell = new GroovyShell(GroovySandbox.createSecureCompilerConfiguration());
        GroovySandbox.runInSandbox(new Runnable() {
            @Override public void run() {
                assertEquals(expected, shell.evaluate(script));
            }
        }, whitelist);
    }

}
