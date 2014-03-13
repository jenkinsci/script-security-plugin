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
import groovy.lang.GroovyShell;
import java.util.Arrays;
import org.codehaus.groovy.runtime.GStringImpl;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AnnotatedWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.GenericWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.Whitelisted;
import static org.junit.Assert.*;
import org.junit.Ignore;
import org.junit.Test;

public class SandboxInterceptorTest {

    @Test public void genericWhitelist() throws Exception {
        assertEvaluate(new GenericWhitelist(), 3, "'foo bar baz'.split(' ').length");
        assertEvaluate(new GenericWhitelist(), false, "def x = null; x != null");
    }

    /** Checks that {@link GString} is handled sanely. */
    @Test public void testGString() throws Exception {
        String clazz = Clazz.class.getName();
        String script = "def x = 1; new " + clazz + "().method(\"foo${x}\")";
        String expected = "-foo1";
        assertEvaluate(new AnnotatedWhitelist(), expected, script);
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " method java.lang.String")), expected, script);
    }

    /** Checks that methods specifically expecting {@link GString} also work. */
    @Test public void testGString2() throws Exception {
        String clazz = Clazz.class.getName();
        String script = "def x = 1; def c = new " + clazz + "(); c.quote(\"-${c.specialize(x)}-${x}-\")";
        String expected = "-1-'1'-";
        assertEvaluate(new AnnotatedWhitelist(), expected, script);
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " specialize java.lang.Object", "method " + clazz + " quote java.lang.Object")), expected, script);
    }

    @Ignore("TODO there are various unhandled cases, such as Closure → SAM, or numeric conversions.")
    @Test public void testNumbers() throws Exception {
        String clazz = Clazz.class.getName();
        String script = "int x = 1; " + clazz + ".incr(x)";
        Long expected = 2L;
        // works but is undesirable: assertEvaluate(new StaticWhitelist(Arrays.asList("staticMethod " + clazz + " incr java.lang.Integer")), expected, script);
        assertEvaluate(new AnnotatedWhitelist(), expected, script);
        // wrapper types must be declared for primitives:
        assertEvaluate(new StaticWhitelist(Arrays.asList("staticMethod " + clazz + " incr java.lang.Long")), expected, script);
    }

    @Ignore("TODO not yet implemented")
    @Test public void staticFields() throws Exception {
        String clazz = Clazz.class.getName();
        assertEvaluate(new StaticWhitelist(Arrays.asList("field " + clazz + " flag")), true, clazz + ".flag=true");
        assertTrue(Clazz.flag);
    }

    @Test public void propertiesAndGettersAndSetters() throws Exception {
        String clazz = Clazz.class.getName();
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "field " + clazz + " prop")), "default", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp")), "default", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "field " + clazz + " prop", "method " + clazz + " getProp")), "default", "new " + clazz + "().prop");
        try {
            assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz)), "should be rejected", "new " + clazz + "().prop");
        } catch (RejectedAccessException x) {
            assertEquals("field " + clazz + " prop", x.getSignature());
        }
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp", "field " + clazz + " prop")), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp", "method " + clazz + " setProp java.lang.String")), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp", "field " + clazz + " prop", "method " + clazz + " setProp java.lang.String")), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        try {
            assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp")), "should be rejected", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        } catch (RejectedAccessException x) {
            assertEquals("field " + clazz + " prop", x.getSignature());
        }
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp2")), "default", "new " + clazz + "().prop2");
        try {
            assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz)), "should be rejected", "new " + clazz + "().prop2");
        } catch (RejectedAccessException x) {
            assertEquals("method " + clazz + " getProp2", x.getSignature());
        }
        assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp2", "method " + clazz + " setProp2 java.lang.String")), "edited", "def c = new " + clazz + "(); c.prop2 = 'edited'; c.getProp2()");
        try {
            assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz, "method " + clazz + " getProp2")), "should be rejected", "def c = new " + clazz + "(); c.prop2 = 'edited'; c.getProp2()");
        } catch (RejectedAccessException x) {
            assertEquals("method " + clazz + " setProp2 java.lang.String", x.getSignature());
        }
        try {
            assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz)), "should be rejected", "new " + clazz + "().nonexistent");
        } catch (RejectedAccessException x) {
            assertEquals(null, x.getSignature());
            assertEquals("unclassified field " + clazz + " nonexistent", x.getMessage());
        }
        try {
            assertEvaluate(new StaticWhitelist(Arrays.asList("new " + clazz)), "should be rejected", "new " + clazz + "().nonexistent = 'edited'");
        } catch (RejectedAccessException x) {
            assertEquals(null, x.getSignature());
            assertEquals("unclassified field " + clazz + " nonexistent", x.getMessage());
        }
    }

    public static final class Clazz {
        static boolean flag;
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
        @Whitelisted static long incr(long x) {
            return x + 1;
        }
        private String prop = "default";
        public String getProp() {
            return prop;
        }
        public void setProp(String prop) {
            this.prop = prop;
        }
        private String _prop2 = "default";
        public String getProp2() {
            return _prop2;
        }
        public void setProp2(String prop2) {
            this._prop2 = prop2;
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
