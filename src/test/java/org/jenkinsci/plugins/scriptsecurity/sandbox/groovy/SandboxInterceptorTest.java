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

import groovy.json.JsonBuilder;
import groovy.lang.Closure;
import groovy.lang.GString;
import groovy.lang.GroovyObjectSupport;
import groovy.lang.GroovyShell;
import groovy.lang.MissingPropertyException;
import groovy.text.SimpleTemplateEngine;
import groovy.text.Template;
import hudson.Functions;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import org.codehaus.groovy.runtime.GStringImpl;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AbstractWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AnnotatedWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.BlanketWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.GenericWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;
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
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " method java.lang.String"), expected, script);
    }

    /** Checks that methods specifically expecting {@link GString} also work. */
    @Test public void testGString2() throws Exception {
        String clazz = Clazz.class.getName();
        String script = "def x = 1; def c = new " + clazz + "(); c.quote(\"-${c.specialize(x)}-${x}-\")";
        String expected = "-1-'1'-";
        assertEvaluate(new AnnotatedWhitelist(), expected, script);
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " specialize java.lang.Object", "method " + clazz + " quote java.lang.Object"), expected, script);
    }

    /**
     * Tests the proper interception of builder-like method.
     */
    @Test public void testInvokeMethod() throws Exception {
        String script = "def builder = new groovy.json.JsonBuilder(); builder.point { x 5; y 3; }; builder.toString()";
        String expected = "{\"point\":{\"x\":5,\"y\":3}}";
        assertEvaluate(new BlanketWhitelist(), expected, script);
        // this whitelisting strategy isn't ideal
        // see https://issues.jenkins-ci.org/browse/JENKINS-24982
        assertEvaluate(new ProxyWhitelist(
            new AbstractWhitelist() {
                @Override
                public boolean permitsMethod(Method method, Object receiver, Object[] args) {
                    if (method.getName().equals("invokeMethod") && receiver instanceof JsonBuilder)
                        return true;
                    if (method.getName().equals("invokeMethod") && receiver instanceof Closure) {
                        Object d = ((Closure) receiver).getDelegate();
                        return d.getClass().getName().equals("groovy.json.JsonDelegate");
                    }
                    if (method.getName().equals("toString") && receiver instanceof JsonBuilder)
                        return true;
                    return false;
                }
            },
            new StaticWhitelist(
                "new groovy.json.JsonBuilder"
//                "method groovy.json.JsonBuilder toString",
//                "method groovy.json.JsonBuilder invokeMethod java.lang.String java.lang.Object"
        )), expected, script);
    }

    @Ignore("TODO there are various unhandled cases, such as Closure → SAM, or numeric conversions, or number → String, or boxing/unboxing.")
    @Test public void testNumbers() throws Exception {
        String clazz = Clazz.class.getName();
        String script = "int x = 1; " + clazz + ".incr(x)";
        Long expected = 2L;
        // works but is undesirable: assertEvaluate(new StaticWhitelist("staticMethod " + clazz + " incr java.lang.Integer")), expected, script);
        assertEvaluate(new AnnotatedWhitelist(), expected, script);
        // wrapper types must be declared for primitives:
        assertEvaluate(new StaticWhitelist("staticMethod " + clazz + " incr java.lang.Long"), expected, script);
    }

    @Test public void staticFields() throws Exception {
        String clazz = Clazz.class.getName();
        assertEvaluate(new StaticWhitelist("staticField " + clazz + " flag"), true, clazz + ".flag=true");
        assertTrue(Clazz.flag);
    }

    @Test public void propertiesAndGettersAndSetters() throws Exception {
        String clazz = Clazz.class.getName();
        assertEvaluate(new StaticWhitelist("new " + clazz, "field " + clazz + " prop"), "default", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp"), "default", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist("new " + clazz, "field " + clazz + " prop", "method " + clazz + " getProp"), "default", "new " + clazz + "().prop");
        assertRejected(new StaticWhitelist("new " + clazz), "field " + clazz + " prop", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp", "field " + clazz + " prop"), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp", "method " + clazz + " setProp java.lang.String"), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp", "field " + clazz + " prop", "method " + clazz + " setProp java.lang.String"), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertRejected(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp"), "field " + clazz + " prop", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp2"), "default", "new " + clazz + "().prop2");
        assertRejected(new StaticWhitelist("new " + clazz), "method " + clazz + " getProp2", "new " + clazz + "().prop2");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp2", "method " + clazz + " setProp2 java.lang.String"), "edited", "def c = new " + clazz + "(); c.prop2 = 'edited'; c.getProp2()");
        assertRejected(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp2"), "method " + clazz + " setProp2 java.lang.String", "def c = new " + clazz + "(); c.prop2 = 'edited'; c.getProp2()");
        try {
            assertEvaluate(new StaticWhitelist("new " + clazz), "should be rejected", "new " + clazz + "().nonexistent");
        } catch (RejectedAccessException x) {
            assertEquals(null, x.getSignature());
            assertEquals("unclassified field " + clazz + " nonexistent", x.getMessage());
        }
        try {
            assertEvaluate(new StaticWhitelist("new " + clazz), "should be rejected", "new " + clazz + "().nonexistent = 'edited'");
        } catch (RejectedAccessException x) {
            assertEquals(null, x.getSignature());
            assertEquals("unclassified field " + clazz + " nonexistent", x.getMessage());
        }
    }

    @Test public void syntheticMethods() throws Exception {
        assertEvaluate(new GenericWhitelist(), 4, "2 + 2");
        assertEvaluate(new GenericWhitelist(), "17", "'' + 17");
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
    
    @Test public void dynamicProperties() throws Exception {
        String dynamic = Dynamic.class.getName();
        String ctor = "new " + dynamic;
        String getProperty = "method groovy.lang.GroovyObject getProperty java.lang.String";
        String setProperty = "method groovy.lang.GroovyObject setProperty java.lang.String java.lang.Object";
        String script = "def d = new " + dynamic + "(); d.prop = 'val'; d.prop";
        assertEvaluate(new StaticWhitelist(ctor, getProperty, setProperty), "val", script);
        assertRejected(new StaticWhitelist(ctor, setProperty), getProperty, script);
        assertRejected(new StaticWhitelist(ctor), setProperty, script);
    }

    public static final class Dynamic extends GroovyObjectSupport {
        private final Map<String,Object> values = new HashMap<String,Object>();
        @Override public Object getProperty(String n) {
            return values.get(n);
        }
        @Override public void setProperty(String n, Object v) {
            values.put(n, v);
        }
    }

    public static final class Special {
        final Object o;
        Special(Object o) {
            this.o = o;
        }
    }

    @Ignore("TODO not yet implemented")
    @Test public void defaultGroovyMethods() throws Exception {
        assertEvaluate(new GenericWhitelist(), Arrays.asList(1, 4, 9), "([1, 2, 3] as int[]).collect({it * it})");
    }

    @Test public void whitelistedIrrelevantInsideScript() throws Exception {
        String clazz = Unsafe.class.getName();
        String wl = Whitelisted.class.getName();
        // @Whitelisted does not grant us access to anything new:
        assertEvaluate(new AnnotatedWhitelist(), "ok", " C.m(); class C {@" + wl + " static String m() {return " + clazz + ".ok();}}");
        assertRejected(new AnnotatedWhitelist(), "staticMethod " + clazz + " explode", "C.m(); class C {@" + wl + " static void m() {" + clazz + ".explode();}}");
        // but do not need @Whitelisted on ourselves:
        assertEvaluate(new AnnotatedWhitelist(), "ok", "C.m(); class C {static String m() {return " + clazz + ".ok();}}");
        assertRejected(new AnnotatedWhitelist(), "staticMethod " + clazz + " explode", "C.m(); class C {static void m() {" + clazz + ".explode();}}");
    }

    @Test public void defSyntax() throws Exception {
        String clazz = Unsafe.class.getName();
        Whitelist w = new ProxyWhitelist(new AnnotatedWhitelist(), /* for some reason def syntax triggers this */new StaticWhitelist("method java.util.Collection toArray"));
        assertEvaluate(w, "ok", "m(); def m() {" + clazz + ".ok()}");
        assertEvaluate(w, "ok", "m(); def static m() {" + clazz + ".ok()}");
        assertRejected(w, "staticMethod " + clazz + " explode", "m(); def m() {" + clazz + ".explode()}");
    }

    public static final class Unsafe {
        @Whitelisted public static String ok() {return "ok";}
        public static void explode() {}
        private Unsafe() {}
    }

    /** Expect errors from {@link org.codehaus.groovy.runtime.NullObject}. */
    @Test public void nullPointerException() throws Exception {
        try {
            assertEvaluate(new ProxyWhitelist(), "should be rejected", "def x = null; x.member");
        } catch (NullPointerException x) {
            assertEquals(Functions.printThrowable(x), "Cannot get property 'member' on null object", x.getMessage());
        }
        try {
            assertEvaluate(new ProxyWhitelist(), "should be rejected", "def x = null; x.member = 42");
        } catch (NullPointerException x) {
            assertEquals(Functions.printThrowable(x), "Cannot set property 'member' on null object", x.getMessage());
        }
        try {
            assertEvaluate(new ProxyWhitelist(), "should be rejected", "def x = null; x.member()");
        } catch (NullPointerException x) {
            assertEquals(Functions.printThrowable(x), "Cannot invoke method member() on null object", x.getMessage());
        }
    }

    @Test public void closures() throws Exception {
        // TODO https://github.com/kohsuke/groovy-sandbox/issues/11 would like that to be rejecting method java.lang.Throwable getMessage
        assertRejected(
                new StaticWhitelist(
                        "method java.util.concurrent.Callable call",
                        "field groovy.lang.Closure delegate",
                        "new java.lang.Exception java.lang.String"),
                "method groovy.lang.GroovyObject getProperty java.lang.String",
                "{-> delegate = new Exception('oops'); message}()"
        );
        // TODO similarly this would preferably be rejecting method java.lang.Throwable printStackTrace
        assertRejected(
                new StaticWhitelist(
                        "method java.util.concurrent.Callable call",
                        "field groovy.lang.Closure delegate",
                        "new java.lang.Exception java.lang.String"),
                "method groovy.lang.GroovyObject invokeMethod java.lang.String java.lang.Object",
                "{-> delegate = new Exception('oops'); printStackTrace()}()"
        );
    }

    @Test public void templates() throws Exception {
        final GroovyShell shell = new GroovyShell(GroovySandbox.createSecureCompilerConfiguration());
        final Template t = new SimpleTemplateEngine(shell).createTemplate("goodbye <%= aspect.toLowerCase() %> world");
        assertEquals("goodbye cruel world", GroovySandbox.runInSandbox(new Callable<String>() {
            @Override public String call() throws Exception {
                return t.make(new HashMap<String,Object>(Collections.singletonMap("aspect", "CRUEL"))).toString();
            }
        }, new StaticWhitelist("method java.lang.String toLowerCase", "method java.io.PrintWriter print java.lang.Object")));
    }
    
    @Test public void selfProperties() throws Exception {
        assertEvaluate(new ProxyWhitelist(), true, "BOOL=true; BOOL");
    }

    @Test public void missingPropertyException() throws Exception {
        try {
            assertEvaluate(new ProxyWhitelist(), "should fail", "GOOP");
        } catch (MissingPropertyException x) {
            assertEquals("GOOP", x.getProperty());
        }
    }

    @Ignore("https://github.com/kohsuke/groovy-sandbox/issues/16")
    @Test public void infiniteLoop() throws Exception {
        assertEvaluate(new BlanketWhitelist(), "abc", "def split = 'a b c'.split(' '); def b = new StringBuilder(); for (i = 0; i < split.length; i++) {println(i); b.append(split[i])}; b.toString()");
    }

    private static void assertEvaluate(Whitelist whitelist, final Object expected, final String script) {
        final GroovyShell shell = new GroovyShell(GroovySandbox.createSecureCompilerConfiguration());
        assertEquals(expected, GroovySandbox.run(shell.parse(script), whitelist));
    }

    private static void assertRejected(Whitelist whitelist, String expectedSignature, String script) {
        try {
            assertEvaluate(whitelist, "should be rejected", script);
        } catch (RejectedAccessException x) {
            assertEquals(x.getMessage(), expectedSignature, x.getSignature());
        }
    }

}
