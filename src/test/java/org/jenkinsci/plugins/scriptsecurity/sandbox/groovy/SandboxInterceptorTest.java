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
import org.codehaus.groovy.runtime.GStringImpl;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AnnotatedWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.Whitelisted;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

public class SandboxInterceptorTest {

    @Test public void genericWhitelist() throws Exception {
        assertEvaluate(new GenericWhitelist(), 3, "'foo bar baz'.split(' ').length");
        assertEvaluate(new GenericWhitelist(), false, "def x = null; x != null");
    }

    /** Checks that {@link GString} is handled sanely. */
    @Ignore // TODO have not yet figured out how to make this work without breaking testGString2; need to patch StaticWhitelist.methodDefinition and friends to consider GString a subtype of String perhaps?
    @Test public void testGString() throws Exception {
        assertEvaluate(new AnnotatedWhitelist(), "-foo1", "def x = 1; new " + Clazz.class.getName() + "().method(\"foo${x}\")");
    }

    /** Checks that methods specifically expecting {@link GString} also work. */
    @Test public void testGString2() throws Exception {
        assertEvaluate(new AnnotatedWhitelist(), "-1-'1'-", "def x = 1; def c = new " + Clazz.class.getName() + "(); c.quote(\"-${c.specialize(x)}-${x}-\")");
    }

    public static final class Clazz {
        @Whitelisted public Clazz() {}
        @Whitelisted public String method(String x) {return "-" + x;}
        @Whitelisted Special specialize(Object o) {
            return new Special(o);
        }
        @Whitelisted String quote(Object o) {
            if (o instanceof GString) {
                GString gs = (GString) o;
                Object[] values = gs.getValues();
                for (int i = 0; i < values.length; i++) {
                    if (values[i] instanceof Special) {
                        values[i] = ((Special) values[i]).o;
                    } else {
                        values[i] = quoteSingle(values[i]);
                    }
                }
                return new GStringImpl(values, gs.getStrings()).toString();
            } else {
                return quoteSingle(o);
            }
        }
        private String quoteSingle(Object o) {
            return "'" + String.valueOf(o) + "'";
        }
    }

    public static final class Special {
        final Object o;
        Special(Object o) {
            this.o = o;
        }
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
