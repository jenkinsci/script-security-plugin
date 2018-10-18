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
import groovy.json.JsonDelegate;
import groovy.lang.GString;
import groovy.lang.GroovyObject;
import groovy.lang.GroovyObjectSupport;
import groovy.lang.GroovyRuntimeException;
import groovy.lang.GroovyShell;
import groovy.lang.MetaMethod;
import groovy.lang.MissingMethodException;
import groovy.lang.MissingPropertyException;
import groovy.lang.Script;
import groovy.text.SimpleTemplateEngine;
import groovy.text.Template;
import hudson.Functions;
import hudson.util.IOUtils;

import java.lang.reflect.Method;
import java.net.URL;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.MultipleCompilationErrorsException;
import org.codehaus.groovy.runtime.GStringImpl;
import org.codehaus.groovy.runtime.InvokerHelper;
import static org.hamcrest.Matchers.*;
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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.jvnet.hudson.test.Issue;

public class SandboxInterceptorTest {

    @Rule public ErrorCollector errors = new ErrorCollector();

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

    @Issue("JENKINS-29541")
    @Test public void substringGString() throws Exception {
        assertEvaluate(new GenericWhitelist(), "hell", "'hello world'.substring(0, 4)");
        assertEvaluate(new GenericWhitelist(), "hell", "def place = 'world'; \"hello ${place}\".substring(0, 4)");
    }

    /**
     * Tests the proper interception of builder-like method.
     */
    @Test public void invokeMethod() throws Exception {
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
                    if (method.getName().equals("invokeMethod") && receiver instanceof JsonDelegate)
                        return true;
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
        try {
            evaluate(new ProxyWhitelist(), "class Real {}; def real = new Real(); real.nonexistent(42)");
            fail();
        } catch (RejectedAccessException x) {
            String message = x.getMessage();
            assertEquals(message, "method groovy.lang.GroovyObject invokeMethod java.lang.String java.lang.Object", x.getSignature());
            assertTrue(message, message.contains("Real nonexistent java.lang.Integer"));
        }
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

    @Issue("JENKINS-34599")
    @Test public void finalFields() throws Exception {
        // Control cases: non-final fields.
        assertEvaluate(new ProxyWhitelist(), 99, "class X {int x = 99}; new X().x");
        assertEvaluate(new ProxyWhitelist(), 99, "class X {int x; X(int x) {this.x = x}}; new X(99).x");
        assertEvaluate(new ProxyWhitelist(), 99, "class X {int x; {this.x = 99}}; new X().x");
        assertEvaluate(new ProxyWhitelist(), 99, "class X {static int x = 99}; X.x");
        assertEvaluate(new ProxyWhitelist(), 99, "class X {static int x; static {x = 99}}; X.x");
        // Control case: field set in initialization expression.
        assertEvaluate(new ProxyWhitelist(), 99, "class X {final int x = 99}; new X().x");
        // Test case: field set in constructor.
        assertEvaluate(new ProxyWhitelist(), 99, "class X {final int x; X(int x) {this.x = x}}; new X(99).x");
        // Test case: field set in instance initializer.
        assertEvaluate(new ProxyWhitelist(), 99, "class X {final int x; {this.x = 99}}; new X().x");
        // Control case: field set in static initialization expression.
        assertEvaluate(new ProxyWhitelist(), 99, "class X {static final int x = 99}; X.x");
        // Test case: field set in static instance initializer.
        assertEvaluate(new ProxyWhitelist(), 99, "class X {static final int x; static {x = 99}}; X.x");
        // Control case: initialization expressions themselves are checked.
        assertRejected(new ProxyWhitelist(), "staticMethod jenkins.model.Jenkins getInstance", "class X {Object x = jenkins.model.Jenkins.instance}; new X().x");
        assertRejected(new ProxyWhitelist(), "staticMethod jenkins.model.Jenkins getInstance", "class X {Object x; {x = jenkins.model.Jenkins.instance}}; new X().x");
        try {
            errors.checkThat(evaluate(new ProxyWhitelist(), "class X {static Object x = jenkins.model.Jenkins.instance}; X.x"), is((Object) "should be rejected"));
        } catch (ExceptionInInitializerError x) {
            errors.checkThat(x.getMessage(), ((RejectedAccessException) x.getCause()).getSignature(), is("staticMethod jenkins.model.Jenkins getInstance"));
        } catch (Throwable t) {
            errors.addError(t);
        }
        try {
            errors.checkThat(evaluate(new ProxyWhitelist(), "class X {static Object x; static {x = jenkins.model.Jenkins.instance}}; X.x"), is((Object) "should be rejected"));
        } catch (ExceptionInInitializerError x) {
            errors.checkThat(x.getMessage(), ((RejectedAccessException) x.getCause()).getSignature(), is("staticMethod jenkins.model.Jenkins getInstance"));
        } catch (Throwable t) {
            errors.addError(t);
        }
        // Control case: when there is no backing field, we should not allow setters to be called.
        String sps = SafePerSe.class.getName();
        assertRejected(new AnnotatedWhitelist(), "method " + sps + " setSecure boolean", "class X extends " + sps + " {X() {this.secure = false}}; new X()");
    }

    @Test public void propertiesAndGettersAndSetters() throws Exception {
        String clazz = Clazz.class.getName();
        assertEvaluate(new StaticWhitelist("new " + clazz, "field " + clazz + " prop"), "default", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp"), "default", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist("new " + clazz, "field " + clazz + " prop", "method " + clazz + " getProp"), "default", "new " + clazz + "().prop");
        assertRejected(new StaticWhitelist("new " + clazz), "method " + clazz + " getProp", "new " + clazz + "().prop");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp", "field " + clazz + " prop"), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp", "method " + clazz + " setProp java.lang.String"), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp", "field " + clazz + " prop", "method " + clazz + " setProp java.lang.String"), "edited", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertRejected(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp"), "method " + clazz + " setProp java.lang.String", "def c = new " + clazz + "(); c.prop = 'edited'; c.getProp()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp2"), "default", "new " + clazz + "().prop2");
        assertRejected(new StaticWhitelist("new " + clazz), "method " + clazz + " getProp2", "new " + clazz + "().prop2");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp2", "method " + clazz + " setProp2 java.lang.String"), "edited", "def c = new " + clazz + "(); c.prop2 = 'edited'; c.getProp2()");
        assertRejected(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp2"), "method " + clazz + " setProp2 java.lang.String", "def c = new " + clazz + "(); c.prop2 = 'edited'; c.getProp2()");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " isProp3"), false, "new " + clazz + "().prop3");
        assertRejected(new StaticWhitelist("new " + clazz), "method " + clazz + " isProp3", "new " + clazz + "().prop3");
        assertEvaluate(new StaticWhitelist("staticMethod " + clazz + " isProp4"), true, clazz + ".prop4");
        assertRejected(new StaticWhitelist(), "staticMethod " + clazz + " isProp4", clazz + ".prop4");
        try {
            evaluate(new StaticWhitelist("new " + clazz), "new " + clazz + "().nonexistent");
            fail();
        } catch (RejectedAccessException x) {
            assertEquals(null, x.getSignature());
            assertEquals("No such field found: field " + clazz + " nonexistent", x.getMessage());
        }
        try {
            evaluate(new StaticWhitelist("new " + clazz), "new " + clazz + "().nonexistent = 'edited'");
            fail();
        } catch (RejectedAccessException x) {
            assertEquals(null, x.getSignature());
            assertEquals("No such field found: field " + clazz + " nonexistent", x.getMessage());
        }
        assertRejected(new StaticWhitelist("new " + clazz), "method " + clazz + " getProp5", "new " + clazz + "().prop5");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp5"), "DEFAULT", "new " + clazz + "().prop5");
        assertRejected(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp5"), "method " + clazz + " setProp5 java.lang.String", "def c = new " + clazz + "(); c.prop5 = 'EDITED'; c.prop5");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp5", "method " + clazz + " setProp5 java.lang.String", "method " + clazz + " rawProp5", "staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods plus java.lang.String java.lang.Object"), "EDITEDedited", "def c = new " + clazz + "(); c.prop5 = 'EDITED'; c.prop5 + c.rawProp5()");
        assertRejected(new StaticWhitelist("new " + clazz), "field " + clazz + " prop5", "new " + clazz + "().@prop5");
        assertEvaluate(new StaticWhitelist("new " + clazz, "field " + clazz + " prop5"), "default", "new " + clazz + "().@prop5");
        assertRejected(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp5"), "field " + clazz + " prop5", "def c = new " + clazz + "(); c.@prop5 = 'edited'; c.prop5");
        assertEvaluate(new StaticWhitelist("new " + clazz, "method " + clazz + " getProp5", "field " + clazz + " prop5"), "EDITED", "def c = new " + clazz + "(); c.@prop5 = 'edited'; c.prop5");
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
        private boolean _prop3;
        public boolean isProp3() {
            return _prop3;
        }
        public void setProp3(boolean prop3) {
            this._prop3 = prop3;
        }
        public static boolean isProp4() {
            return true;
        }
        private String prop5 = "default";
        public String getProp5() {
            return prop5.toUpperCase(Locale.ENGLISH);
        }
        public void setProp5(String value) {
            prop5 = value.toLowerCase(Locale.ENGLISH);
        }
        public String rawProp5() {
            return prop5;
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

    @Test public void mapProperties() throws Exception {
        assertEvaluate(new GenericWhitelist(), 42, "def m = [:]; m.answer = 42; m.answer");
    }

    public static final class Special {
        final Object o;
        Special(Object o) {
            this.o = o;
        }
    }

    @Issue({"JENKINS-25119", "JENKINS-27725"})
    @Test public void defaultGroovyMethods() throws Exception {
        assertRejected(new ProxyWhitelist(), "staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods toInteger java.lang.String", "'123'.toInteger();");
        assertEvaluate(new GenericWhitelist(), 123, "'123'.toInteger();");
        assertEvaluate(new GenericWhitelist(), Arrays.asList(1, 4, 9), "([1, 2, 3] as int[]).collect({x -> x * x})");
        assertEvaluate(new GenericWhitelist(), Arrays.asList(1, 4, 9), "([1, 2, 3] as int[]).collect({it * it})");
        // cover others from DgmConverter:
        assertEvaluate(new GenericWhitelist(), "1970", "new Date(0).format('yyyy', TimeZone.getTimeZone('GMT'))");
        assertEvaluate(new GenericWhitelist(), /* actual value sensitive to local TZ */ DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(new Date(0)), "new Date(0).dateTimeString");
        // cover get* and is* methods:
        assertEvaluate(new GenericWhitelist(), 5, "'hello'.chars.length");
        assertEvaluate(new GenericWhitelist(), true, "'42'.number");
        // TODO should also cover set* methods, though these seem rare
        // TODO check DefaultGroovyStaticMethods also (though there are few useful & safe calls there)
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

    @Issue("JENKINS-34741")
    @Test public void structConstructor() throws Exception {
        assertEvaluate(new StaticWhitelist(), "ok", "class C {String f}; new C(f: 'ok').f");
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
    @Issue("kohsuke/groovy-sandbox #15")
    @Test public void nullPointerException() throws Exception {
        try {
            evaluate(new ProxyWhitelist(), "def x = null; x.member");
            fail();
        } catch (NullPointerException x) {
            assertEquals(Functions.printThrowable(x), "Cannot get property 'member' on null object", x.getMessage());
        }
        try {
            evaluate(new ProxyWhitelist(), "def x = null; x.member = 42");
            fail();
        } catch (NullPointerException x) {
            assertEquals(Functions.printThrowable(x), "Cannot set property 'member' on null object", x.getMessage());
        }
        try {
            evaluate(new ProxyWhitelist(), "def x = null; x.member()");
            fail();
        } catch (NullPointerException x) {
            assertEquals(Functions.printThrowable(x), "Cannot invoke method member() on null object", x.getMessage());
        }
    }

    /**
     * Tests the method invocation / property access through closures.
     *
     * <p>
     * Groovy closures act as a proxy when it comes to property/method access. Based on the configuration, it can
     * access those from some combination of owner/delegate. As this is an important building block for custom DSL,
     * script-security understands this logic and checks access at the actual target of the proxy, so that Closures
     * can be used safely.
     */
    @Test public void closureDelegate() throws Exception {
        ProxyWhitelist rules = new ProxyWhitelist(new StaticWhitelist(
            "new java.lang.Exception java.lang.String",
            "method java.util.concurrent.Callable call",
            "method groovy.lang.Closure setDelegate java.lang.Object"));
        assertRejected(rules,
                "method java.lang.Throwable getMessage",
                "{-> delegate = new Exception('oops'); message}()"
        );
        assertRejected(
                rules,
                "method java.lang.Throwable printStackTrace",
                "{-> delegate = new Exception('oops'); printStackTrace()}()"
        );

        rules = new ProxyWhitelist(new GenericWhitelist(), new StaticWhitelist("new java.awt.Point"));
        { // method access
            assertEvaluate(rules, 3,
                    StringUtils.join(Arrays.asList(
                            "class Dummy { def getX() { return 3; } }",
                            "def c = { -> getX() };",
                            "c.resolveStrategy = Closure.DELEGATE_ONLY;",
                            "c.delegate = new Dummy();",
                            "return c();"
                    ), "\n"));
            assertRejected(rules, "method java.awt.geom.Point2D getX",
                    StringUtils.join(Arrays.asList(
                            "def c = { -> getX() };",
                            "c.resolveStrategy = Closure.DELEGATE_ONLY;",
                            "c.delegate = new java.awt.Point();",
                            "return c();"
                    ), "\n"));
        }
        {// property access
            assertEvaluate(rules, 3,
                    StringUtils.join(Arrays.asList(
                            "class Dummy { def getX() { return 3; } }",
                            "def c = { -> x };",
                            "c.resolveStrategy = Closure.DELEGATE_ONLY;",
                            "c.delegate = new Dummy();",
                            "return c();"
                    ), "\n"));
            assertRejected(rules, "method java.awt.geom.Point2D getX",
                    StringUtils.join(Arrays.asList(
                            "def c = { -> x };",
                            "c.resolveStrategy = Closure.DELEGATE_ONLY;",
                            "c.delegate = new java.awt.Point();",
                            "return c();"
                    ), "\n"));
        }
    }

    @Test public void metaClassDelegate() throws Exception {
        new GroovyShell().evaluate("String.metaClass.getAnswer = {-> return 42}"); // privileged operation
        assertEvaluate(new StaticWhitelist(), 42, "'existence'.getAnswer()");
        assertEvaluate(new StaticWhitelist(), 42, "'existence'.answer");
        assertRejected(new GenericWhitelist(), "staticMethod java.lang.System exit int", "def c = System.&exit; c(1)");
    }

    @Issue("JENKINS-28277")
    @Test public void curry() throws Exception {
        assertEvaluate(new GenericWhitelist(), 'h', "def charAt = {idx, str -> str.charAt(idx)}; def firstChar = charAt.curry(0); firstChar 'hello'");
        assertEvaluate(new GenericWhitelist(), 'h', "def charOfHello = 'hello'.&charAt; def firstCharOfHello = charOfHello.curry(0); firstCharOfHello()");
        assertEvaluate(new GenericWhitelist(), 'h', "def charAt = {str, idx -> str.charAt(idx)}; def firstChar = charAt.ncurry(1, 0); firstChar 'hello'");
    }

    @Issue("JENKINS-34739")
    @Test public void varargs() throws Exception {
        // Control cases:
        ProxyWhitelist wl = new ProxyWhitelist(new GenericWhitelist(), new AnnotatedWhitelist());
        assertEvaluate(wl, 0, "class UsesVarargs {static int len(String... vals) {vals.length}}; UsesVarargs.len(new String[0])");
        assertEvaluate(wl, 3, "class UsesVarargs {static int len(String... vals) {vals.length}}; UsesVarargs.len(['one', 'two', 'three'] as String[])");
        String uv = UsesVarargs.class.getName();
        assertEvaluate(wl, 0, uv + ".len(new String[0])");
        assertEvaluate(wl, 3, uv + ".len(['one', 'two', 'three'] as String[])");
        assertEvaluate(wl, 0, uv + ".sum(new int[0])");
        assertEvaluate(wl, 6, uv + ".sum([1, 2, 3] as int[])");
        assertEvaluate(wl, 3, uv + ".xlen(3, new String[0])");
        assertEvaluate(wl, 6, uv + ".xlen(3, ['one', 'two', 'three'] as String[])");
        assertEvaluate(wl, "one,two,three", uv + ".join(',', ['one', 'two', 'three'] as String[])");
        assertRejected(wl, "staticMethod " + uv + " explode java.lang.String[]", uv + ".explode(new String[0])");
        assertRejected(wl, "staticMethod " + uv + " explode java.lang.String[]", uv + ".explode(['one', 'two', 'three'] as String[])");
        // Test cases:
        assertEvaluate(wl, 0, "class UsesVarargs {static int len(String... vals) {vals.length}}; UsesVarargs.len()");
        assertEvaluate(wl, 3, "class UsesVarargs {static int len(String... vals) {vals.length}}; UsesVarargs.len('one', 'two', 'three')");
        assertEvaluate(wl, 0, uv + ".len()");
        assertEvaluate(wl, 3, uv + ".xlen(3)");
        assertEvaluate(wl, 0, uv + ".sum()");
        assertEvaluate(wl, 6, uv + ".sum(1, 2, 3)");
        assertEvaluate(wl, 3, uv + ".len('one', 'two', 'three')");
        assertEvaluate(wl, 6, uv + ".xlen(3, 'one', 'two', 'three')");
        assertEvaluate(wl, "one,two,three", uv + ".join(',', 'one', 'two', 'three')");
        assertRejected(wl, "staticMethod " + uv + " explode java.lang.String[]", uv + ".explode()");
        assertRejected(wl, "staticMethod " + uv + " explode java.lang.String[]", uv + ".explode('one', 'two', 'three')");
    }
    public static class UsesVarargs {
        @Whitelisted
        public static int len(String... vals) {
            return vals.length;
        }
        @Whitelisted
        public static int sum(int... numbers) {
            int sum = 0;
            for (int number : numbers) {
                sum += number;
            }
            return sum;
        }
        @Whitelisted
        public static int xlen(int x, String... vals) {
            return x + vals.length;
        }
        @Whitelisted
        public static String join(String sep, String... vals) {
            return StringUtils.join(vals, sep);
        }
        public static void explode(String... vals) {}
        @Whitelisted
        public static String varargsMethod(Integer i, Boolean b, StringContainer... s) {
            return i.toString() + "-" + b.toString() + "-" + StringUtils.join(s, "-");
        }
    }

    public static final class StringContainer {
        final String o;

        @Whitelisted
        public StringContainer(String o) {
            this.o = o;
        }

        @Whitelisted
        @Override
        public String toString() {
            return o;
        }
    }

    @Test public void templates() throws Exception {
        final GroovyShell shell = new GroovyShell(GroovySandbox.createSecureCompilerConfiguration());
        final Template t = new SimpleTemplateEngine(shell).createTemplate("goodbye <%= aspect.toLowerCase() %> world");
        assertEquals("goodbye cruel world", GroovySandbox.runInSandbox(new Callable<String>() {
            @Override public String call() throws Exception {
                return t.make(new HashMap<String,Object>(Collections.singletonMap("aspect", "CRUEL"))).toString();
            }
        }, new ProxyWhitelist(new StaticWhitelist("method java.lang.String toLowerCase"), new GenericWhitelist())));
    }

    @Test public void selfProperties() throws Exception {
        assertEvaluate(new ProxyWhitelist(), true, "BOOL=true; BOOL");
    }

    @Test public void missingPropertyException() throws Exception {
        try {
            evaluate(new ProxyWhitelist(), "GOOP");
            fail();
        } catch (MissingPropertyException x) {
            assertEquals("GOOP", x.getProperty());
        }
    }

    @Test public void specialScript() throws Exception {
        CompilerConfiguration cc = GroovySandbox.createSecureCompilerConfiguration();
        cc.setScriptBaseClass(SpecialScript.class.getName());
        GroovyShell shell = new GroovyShell(cc);
        Whitelist wl = new AbstractWhitelist() {
            @Override public boolean permitsMethod(Method method, Object receiver, Object[] args) {
                return method.getDeclaringClass() == GroovyObject.class && method.getName().equals("getProperty") && receiver instanceof SpecialScript && args[0].equals("magic");
            }
        };
        assertEquals(42, GroovySandbox.run(shell.parse("magic"), wl));
        try {
            GroovySandbox.run(shell.parse("boring"), wl);
        } catch (MissingPropertyException x) {
            assertEquals("boring", x.getProperty());
        }
    }
    public static abstract class SpecialScript extends Script {
        @Override public Object getProperty(String property) {
            if (property.equals("magic")) {
                return 42;
            }
            return super.getProperty(property);
        }
    }

    @Issue("JENKINS-46757")
    @Test public void properties() throws Exception {
        String script = "def properties = new Properties()";
        assertRejected(new StaticWhitelist(), "new java.util.Properties", script);
        assertEvaluate(new StaticWhitelist("new java.util.Properties"), new Properties(), script);
        script = "Properties properties = new Properties()";
        assertRejected(new StaticWhitelist(), "new java.util.Properties", script);
        assertEvaluate(new StaticWhitelist("new java.util.Properties"), new Properties(), script);
    }

    @Issue("SECURITY-566")
    @Test public void typeCoercion() throws Exception {
        assertRejected(new StaticWhitelist("staticMethod java.util.Locale getDefault"), "method java.util.Locale getCountry", "interface I {String getCountry()}; (Locale.getDefault() as I).getCountry()");
        assertRejected(new StaticWhitelist("staticMethod java.util.Locale getDefault"), "method java.util.Locale getCountry", "interface I {String getCountry()}; (Locale.getDefault() as I).country");
        assertRejected(new ProxyWhitelist(), "staticMethod java.util.Locale getAvailableLocales", "interface I {Locale[] getAvailableLocales()}; (Locale as I).getAvailableLocales()");
        assertRejected(new ProxyWhitelist(), "staticMethod java.util.Locale getAvailableLocales", "interface I {Locale[] getAvailableLocales()}; (Locale as I).availableLocales");
    }

    @Issue("SECURITY-580")
    @Test public void positionalConstructors() throws Exception {
        assertRejected(new ProxyWhitelist(), "new java.lang.Boolean java.lang.String", "['true'] as Boolean");
        assertEvaluate(new StaticWhitelist("new java.lang.Boolean java.lang.String"), true, "['true'] as Boolean");
        String cc = "staticMethod org.kohsuke.groovy.sandbox.impl.Checker checkedCast java.lang.Class java.lang.Object boolean boolean boolean";
        assertRejected(new StaticWhitelist(cc), "new java.lang.Boolean java.lang.String", "Boolean x = ['true']; x");
        assertEvaluate(new StaticWhitelist(cc, "new java.lang.Boolean java.lang.String"), true, "Boolean x = ['true']; x");
        assertRejected(new ProxyWhitelist(), "new java.util.TreeMap java.util.Map", "[k: 1] as TreeMap");
        assertEvaluate(new StaticWhitelist("new java.util.TreeMap java.util.Map"), Collections.singletonMap("k", 1), "[k: 1] as TreeMap");
        assertRejected(new StaticWhitelist(cc), "new java.util.TreeMap java.util.Map", "TreeMap x = [k: 1]; x");
        assertEvaluate(new StaticWhitelist(cc, "new java.util.TreeMap java.util.Map"), Collections.singletonMap("k", 1), "TreeMap x = [k: 1]; x");
        // These go through a different code path:
        assertEvaluate(new ProxyWhitelist(), Arrays.asList(1), "[1] as LinkedList");
        assertEvaluate(new ProxyWhitelist(), Arrays.asList("v"), "['v'] as LinkedList");
        assertEvaluate(new StaticWhitelist(cc), Arrays.asList(1), "LinkedList x = [1]; x");
        assertEvaluate(new StaticWhitelist(cc), Arrays.asList("v"), "LinkedList x = ['v']; x");
        assertEvaluate(new ProxyWhitelist(), Arrays.asList(1), "int[] a = [1]; a as LinkedList");
        assertEvaluate(new ProxyWhitelist(), Arrays.asList("v"), "String[] a = ['v']; a as LinkedList");
        assertEvaluate(new StaticWhitelist(cc), Arrays.asList("v"), "String[] a = ['v']; LinkedList x = a; x");
        assertEvaluate(new StaticWhitelist(cc), Arrays.asList("v"), "String[] a = ['v']; LinkedList x = a; x");
        /* TODO casting arrays is not yet supported:
        assertRejected(new StaticWhitelist(cc), "new java.lang.Boolean java.lang.String", "String[] a = ['true']; Boolean x = a; x");
        assertEvaluate(new StaticWhitelist(cc, "new java.lang.Boolean java.lang.String"), true, "String[] a = ['true']; Boolean x = a; x");
        assertRejected(new ProxyWhitelist(), "new java.lang.Boolean java.lang.String", "String[] a = ['true']; a as Boolean");
        assertEvaluate(new StaticWhitelist("new java.lang.Boolean java.lang.String"), true, "String[] a = ['true']; a as Boolean");
        */
        /* TODO tuple assignment is not yet supported:
        assertRejected(new ProxyWhitelist(), "new java.util.LinkedList java.util.Collection", "String[] a = ['v']; def (LinkedList x, int y) = [a, 1]; x");
        assertEvaluate(new StaticWhitelist("new java.util.LinkedList java.util.Collection"), Arrays.asList("v"), "String[] a = ['v']; def (LinkedList x, int y) = [a, 1]; x");
        */
    }

    @Issue("kohsuke/groovy-sandbox #16")
    @Test public void infiniteLoop() throws Exception {
        assertEvaluate(new BlanketWhitelist(), "abc", "def split = 'a b c'.split(' '); def b = new StringBuilder(); for (i = 0; i < split.length; i++) {println(i); b.append(split[i])}; b.toString()");
    }

    @Issue("JENKINS-25118")
    @Test public void primitiveTypes() throws Exception {
        // Some String operations:
        assertRejected(new ProxyWhitelist(), "method java.lang.CharSequence charAt int", "'123'.charAt(1);");
        assertEvaluate(new StaticWhitelist("method java.lang.CharSequence charAt int"), '2', "'123'.charAt(1);");
        // Unrelated to math:
        assertRejected(new ProxyWhitelist(), "staticMethod java.lang.Integer getInteger java.lang.String", "Integer.getInteger('whatever')");
        // Some of http://groovy-lang.org/operators.html#Operator-Overloading on numbers are handled internally:
        assertEvaluate(new ProxyWhitelist(), 4, "2 + 2");
        assertEvaluate(new ProxyWhitelist(), 4, "2.plus(2)");
        // Others are handled via DefaultGroovyMethods:
        assertEvaluate(new GenericWhitelist(), 4, "2 ** 2");
        assertEvaluate(new GenericWhitelist(), 4, "2.power(2)");
        assertEvaluate(new GenericWhitelist(), "23", "'2' + 3");
    }

    @Test public void ambiguousOverloads() {
        try {
            evaluate(new AnnotatedWhitelist(), Ambiguity.class.getName() + ".m(null)");
            fail("Ambiguous overload is an error in Groovy 2");
        } catch(GroovyRuntimeException e) {
            // OK
        }
    }

    public static final class Ambiguity {
        @Whitelisted public static boolean m(String x) {return true;}
        @Whitelisted public static boolean m(URL x) {return true;}
    }

    @Test public void regexps() throws Exception {
        assertEvaluate(new GenericWhitelist(), "goodbye world", "def text = 'hello world'; def matcher = text =~ 'hello (.+)'; matcher ? \"goodbye ${matcher[0][1]}\" : 'fail'");
    }

    @Test public void splitAndJoin() throws Exception {
        assertEvaluate(new GenericWhitelist(), Collections.singletonMap("part0", "one\ntwo"), "def list = [['one', 'two']]; def map = [:]; for (int i = 0; i < list.size(); i++) {map[\"part${i}\"] = list.get(i).join(\"\\n\")}; map");
    }

    public static class ClassWithInvokeMethod extends GroovyObjectSupport {
        @Override
        public Object invokeMethod(String name, Object args) {
            throw new IllegalStateException();
        }
    }

    @Test public void invokeMethod_vs_DefaultGroovyMethods() throws Exception {
        // Closure defines the invokeMethod method, and asBoolean is defined on DefaultGroovyMethods.
        // the method dispatching in this case is that c.asBoolean() resolves to DefaultGroovyMethods.asBoolean()
        // and not invokeMethod("asBoolean")

        // calling asBoolean shouldn't go through invokeMethod
        MetaMethod m1 = InvokerHelper.getMetaClass(ClassWithInvokeMethod.class).pickMethod("asBoolean",new Class[0]);
        assertNotNull(m1);
        assertTrue((Boolean) m1.invoke(new ClassWithInvokeMethod(), new Object[0]));

        // as such, it should be allowed so long as asBoolean is whitelisted
        assertEvaluate(
                new ProxyWhitelist(
                        new GenericWhitelist(),
                        new StaticWhitelist("new " + ClassWithInvokeMethod.class.getName())
                ),
                true,
                "def c = new " + ClassWithInvokeMethod.class.getCanonicalName() + "(); c.asBoolean()"
        );
    }

    @Issue({"JENKINS-42563", "SECURITY-582"})
    @Test public void superCalls() throws Exception {
        String sps = SafePerSe.class.getName();
        assertRejected(new AnnotatedWhitelist(), "method " + sps + " dangerous", "class C extends " + sps + " {void dangerous() {super.dangerous()}}; new C().dangerous()");
        assertRejected(new AnnotatedWhitelist(), "method " + sps + " dangerous", "class C extends " + sps + " {void x() {super.dangerous()}}; new C().x()");
        assertRejected(new StaticWhitelist(), "new java.lang.Exception java.lang.String", "class X1 extends Exception {X1(String x) {super(x)}}; new X1('x')");
        assertEvaluate(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception java.lang.String"), "X1: x", "class X1 extends Exception {X1(String x) {super(x)}}; new X1('x').toString()");
        assertRejected(new StaticWhitelist(), "new java.lang.Exception", "class X2 extends Exception {X2() {}}; new X2()");
        assertEvaluate(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception"), "X2", "class X2 extends Exception {X2() {}}; new X2().toString()");
        assertRejected(new StaticWhitelist(), "new java.lang.Exception", "class X3 extends Exception {}; new X3()");
        assertEvaluate(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception"), "X3", "class X3 extends Exception {}; new X3().toString()");
        assertRejected(new StaticWhitelist(), "new java.lang.Exception java.lang.String", "class X4 extends Exception {X4(int x) {this(x + 1, true)}; X4(int x, boolean b) {super(/$x$b/)}}; new X4(1)");
        assertEvaluate(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception java.lang.String"), "X4: 2true", "class X4 extends Exception {X4(int x) {this(x + 1, true)}; X4(int x, boolean b) {super(/$x$b/)}}; new X4(1).toString()");
        assertRejected(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception java.lang.String"), "method java.lang.String toUpperCase", "class X5 extends Exception {X5(String x) {this(x.toUpperCase(), true)}; X5(String x, boolean b) {super(x)}}; new X5('x')");
        assertRejected(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception java.lang.String"), "method java.lang.String toUpperCase", "class X6 extends Exception {X6(String x) {super(x.toUpperCase())}}; new X6('x')");
        assertRejected(new StaticWhitelist("method java.lang.Object toString", "new java.lang.Exception"), "new java.lang.Object", "class X7 extends Exception {X7(String x) {new Object()}}; new X7('x')");
    }
    public static class SafePerSe {
        @Whitelisted
        public SafePerSe() {}
        public void dangerous() {}
        public void setSecure(boolean x) {}
    }

    @Test public void keywordsAndOperators() throws Exception {
        String script = IOUtils.toString(this.getClass().getResourceAsStream("SandboxInterceptorTest/all.groovy"));
        assertEvaluate(new GenericWhitelist(), null, script);
    }

    @Issue("JENKINS-31234")
    @Test public void calendarGetInstance() throws Exception {
        assertEvaluate(new GenericWhitelist(), true, "Calendar.getInstance().get(Calendar.DAY_OF_MONTH) < 32");
        assertEvaluate(new GenericWhitelist(), true, "Calendar.instance.get(Calendar.DAY_OF_MONTH) < 32");
    }

    @Issue("JENKINS-31701")
    @Test public void primitiveWidening() throws Exception {
        assertEvaluate(new AnnotatedWhitelist(), 4L, SandboxInterceptorTest.class.getName() + ".usePrimitive(2)");
    }
    @Whitelisted public static long usePrimitive(long x) {
        return x + 2;
    }

    @Issue("JENKINS-32211")
    @Test public void tokenize() throws Exception {
        assertEvaluate(new GenericWhitelist(), 3, "'foo bar baz'.tokenize().size()");
        assertEvaluate(new GenericWhitelist(), 3, "'foo bar baz'.tokenize(' ').size()");
        assertEvaluate(new GenericWhitelist(), 3, "'foo bar baz'.tokenize('ba').size()");
    }

    @Issue("JENKINS-33023")
    @Test public void enums() throws Exception {
        String script = "enum Thing {\n"
            + "  FIRST(\"The first thing\");\n"
            + "  String description;\n"
            + "  public Thing(String description) {\n"
            + "    this.description = description;\n"
            + "  }\n"
            + "}\n"
            + "Thing.values()[0].description\n";
        String expected = "The first thing";
        assertEvaluate(new GenericWhitelist(), expected, script);
        String e = E.class.getName();
        ProxyWhitelist wl = new ProxyWhitelist(new GenericWhitelist(), new AnnotatedWhitelist());
        assertEvaluate(wl, 2, e + ".TWO.getN()");
        assertRejected(wl, "method " + e + " explode", e + ".TWO.explode()");
        assertEvaluate(wl, "TWO", e + ".TWO.name()");
        assertRejected(wl, "staticField " + e + " ONE", e + ".ONE.name()");
    }
    public enum E {
        ONE(1),
        @Whitelisted
        TWO(2);
        private final int n;
        private E(int n) {
            this.n = n;
        }
        @Whitelisted
        public int getN() {
            return n;
        }
        public void explode() {}
    }

    @Test public void staticMethodsCannotBeOverridden() throws Exception {
        assertRejected(new StaticWhitelist(), "staticMethod jenkins.model.Jenkins getInstance", "jenkins.model.Jenkins.getInstance()");
        assertRejected(new StaticWhitelist(), "staticMethod jenkins.model.Jenkins getInstance", "jenkins.model.Jenkins.instance");
        assertRejected(new StaticWhitelist(), "staticMethod hudson.model.Hudson getInstance", "hudson.model.Hudson.getInstance()");
        assertRejected(new StaticWhitelist(), "staticMethod hudson.model.Hudson getInstance", "hudson.model.Hudson.instance");
    }

    private static Object evaluate(Whitelist whitelist, String script) {
        GroovyShell shell = new GroovyShell(GroovySandbox.createSecureCompilerConfiguration());
        Object actual = GroovySandbox.run(shell.parse(script), whitelist);
        if (actual instanceof GString) {
            actual = actual.toString(); // for ease of comparison
        }
        return actual;
    }

    private void assertEvaluate(Whitelist whitelist, Object expected, String script) {
        assertEvaluate(whitelist, expected, script, errors);
    }

    public static void assertEvaluate(Whitelist whitelist, Object expected, String script, ErrorCollector errors) {
        try {
            Object actual = evaluate(whitelist, script);
            errors.checkThat(actual, is(expected));
        } catch (Throwable t) {
            errors.addError(t);
        }
        try {
            Object actual = new GroovyShell().evaluate(script);
            if (actual instanceof GString) {
                actual = actual.toString();
            }
            errors.checkThat("control case", actual, is(expected));
        } catch (Throwable t) {
            errors.addError(t);
        }
    }

    private void assertRejected(Whitelist whitelist, String expectedSignature, String script) {
        assertRejected(whitelist, expectedSignature, script, errors);
    }

    public static void assertRejected(Whitelist whitelist, String expectedSignature, String script, ErrorCollector errors) {
        try {
            Object actual = evaluate(whitelist, script);
            errors.checkThat(actual, is((Object) "should be rejected"));
        } catch (RejectedAccessException x) {
            errors.checkThat(x.getMessage(), x.getSignature(), is(expectedSignature));
        } catch (Throwable t) {
            errors.addError(t);
        }
    }

    @Issue("JENKINS-37129")
    @Test public void methodMissingException() throws Exception {
        // test: trying to call a nonexistent method
        try {
            evaluate(new GenericWhitelist(), "[].noSuchMethod()");
            fail();
        } catch (MissingMethodException e) {
            assertEquals(e.getType(),ArrayList.class);
            assertThat(e.getMethod(),is("noSuchMethod"));
        }

        // control: trying to call an existing method that's not safe
        assertRejected(new GenericWhitelist(), "method java.lang.Class getClassLoader", "[].class.classLoader");
    }

    @Issue("JENKINS-46088")
    @Test
    public void matcherTypeAssignment() throws Exception {
        assertEvaluate(new GenericWhitelist(), "goodbye world", "def text = 'hello world'; java.util.regex.Matcher matcher = text =~ 'hello (.+)'; matcher ? \"goodbye ${matcher[0][1]}\" : 'fail'");
    }

    @Issue("JENKINS-46088")
    @Test
    public void rhsOfDeclarationTransformed() throws Exception {
        assertRejected(new StaticWhitelist(), "staticMethod jenkins.model.Jenkins getInstance", "jenkins.model.Jenkins x = jenkins.model.Jenkins.getInstance()");
    }

    @Issue("JENKINS-46191")
    @Test
    public void emptyDeclaration() throws Exception {
        assertEvaluate(new GenericWhitelist(), "abc", "String a; a = 'abc'; return a");
    }

    @Issue("JENKINS-46358")
    @Test
    public void validFromAnyDGMClass() throws Exception {
        // This verifies that we pick up a valid DGM-style method from a class other than DefaultGroovyMethods
        assertEvaluate(new GenericWhitelist(), "alppe", "String a = 'apple'; return a.replaceFirst('ppl') { it.reverse() }");
    }

    @Issue("JENKINS-46391")
    @Test
    public void newPattern() throws Exception {
        assertEvaluate(new GenericWhitelist(), true, "def f = java.util.regex.Pattern.compile('f.*'); return f.matcher('foo').matches()");
    }

    @Issue("JENKINS-46391")
    @Test
    public void tildePattern() throws Exception {
        assertEvaluate(new GenericWhitelist(), Pattern.class, "def f = ~/f.*/; return f.class");
    }

    @Issue("JENKINS-35294")
    @Test
    public void enumWithVarargs() throws Exception {
        String script = "enum Thing {\n"
                + "  FIRST(\"The first thing\")\n"
                + "  String[] descriptions;\n"
                + "  public Thing(String... descriptions) {\n"
                + "    this.descriptions = descriptions;\n"
                + "  }\n"
                + "}\n"
                + "Thing.values()[0].descriptions[0]\n";
        String expected = "The first thing";
        assertEvaluate(new GenericWhitelist(), expected, script);
    }

    @Issue("JENKINS-35294")
    @Test
    public void enumWithStringAndVarargs() throws Exception {
        String script = "enum Thing {\n"
                + "  FIRST(\"The first thing\")\n"
                + "  String description;\n"
                + "  public Thing(String description, int... unused) {\n"
                + "    this.description = description;\n"
                + "  }\n"
                + "}\n"
                + "Thing.values()[0].description\n";
        String expected = "The first thing";
        assertEvaluate(new GenericWhitelist(), expected, script);
    }

    @Issue("JENKINS-44557")
    @Test
    public void varArgsWithGString() throws Exception {
        ProxyWhitelist wl = new ProxyWhitelist(new GenericWhitelist(), new AnnotatedWhitelist());
        String uv = UsesVarargs.class.getName();

        assertEvaluate(wl, 3, "def twoStr = 'two'; " + uv + ".len('one', \"${twoStr}\", 'three')");
    }

    @Issue("JENKINS-47893")
    @Test
    public void varArgsWithOtherArgs() throws Exception {
        ProxyWhitelist wl = new ProxyWhitelist(new GenericWhitelist(), new AnnotatedWhitelist());
        String uv = UsesVarargs.class.getName();
        String sc = StringContainer.class.getName();
        String script = sc + " a = new " + sc + "(\"a\")\n"
                + sc + " b = new " + sc + "(\"b\")\n"
                + sc + " c = new " + sc + "(\"c\")\n"
                + "return " + uv + ".varargsMethod(4, true, a, b, c)\n";

        String expected = "4-true-a-b-c";
        assertEvaluate(wl, expected, script);
    }

    @Issue("JENKINS-48364")
    @Test
    public void nullFirstVarArg() throws Exception {
        ProxyWhitelist wl = new ProxyWhitelist(new GenericWhitelist(), new AnnotatedWhitelist());
        String uv = UsesVarargs.class.getName();

        String script = "return " + uv + ".join(':', null, 'def', 'ghi')\n";
        String expected = ":def:ghi";
        assertEvaluate(wl, expected, script);
    }

    @Issue("JENKINS-46213")
    @Test
    public void varArgsOnStaticDeclaration() throws Exception {
        String script = "class Explode {\n" +
                "  static TEST_FMT = 'a:%s b:%s'\n" +
                "  static STATIC_TEST = sprintf(\n" +
                "    TEST_FMT,\n" +
                "    '1',\n" +
                "    '2',\n" +
                "  )\n" +
                "  String fieldTest = sprintf(\n" +
                "    TEST_FMT,\n" +
                "    '3',\n" +
                "    '4',\n" +
                "  )\n" +
                "}\n" +
                "def ex = new Explode()\n" +
                "return \"${Explode.STATIC_TEST} ${ex.fieldTest}\"\n";

        assertEvaluate(new StaticWhitelist("staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods sprintf java.lang.Object java.lang.String java.lang.Object[]"),
                "a:1 b:2 a:3 b:4",
                script);
    }

    @Issue("SECURITY-663")
    @Test
    public void castAsFile() throws Exception {
        assertRejected(new GenericWhitelist(), "new java.io.File java.lang.String",
                "def s = []; ('/tmp/foo' as File).each { s << it }\n");
    }

    @Issue("JENKINS-48501")
    @Test
    public void nullInVarArgsAsArray() throws Exception {
        String script = "def TEST_FMT = 'a:%s b:%s c:%s d:%s'\n" +
                "String s = sprintf(TEST_FMT, null, '2', '3', '4')\n" +
                "return s\n";
        assertEvaluate(new StaticWhitelist("staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods sprintf java.lang.Object java.lang.String java.lang.Object[]"),
                "a:null b:2 c:3 d:4",
                script);
    }

    public static class NonArrayConstructorList extends ArrayList<String> {
        public NonArrayConstructorList(boolean choiceOne, boolean choiceTwo) {
            if (choiceOne) {
                this.add("one");
            }
            if (choiceTwo) {
                this.add("two");
            }
        }
    }

    @Issue("JENKINS-50380")
    @Test
    public void checkedCastWhenAssignable() throws Exception {
        String nacl = NonArrayConstructorList.class.getName();
        // pre groovy-sandbox-1.18, results in unclassified new org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxInterceptorTest$NonArrayConstructorList java.lang.String
        assertEvaluate(new StaticWhitelist("new org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxInterceptorTest$NonArrayConstructorList boolean boolean",
                        "staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods join java.util.Collection java.lang.String"),
                "one",
                nacl + " foo = new " + nacl + "(true, false); return foo.join('')");

    }

    public static class SimpleNamedBean {
        private String name;

        @Whitelisted
        public SimpleNamedBean(String n) {
            this.name = n;
        }

        @Whitelisted
        public String getName() {
            return name;
        }

        // This is not whitelisted for test purposes to be sure we still do checks.
        public String getOther() {
            return name;
        }
    }

    @Issue("JENKINS-50470")
    @Test
    public void checkedGetPropertyOnCollection() throws Exception {
        String snb = SimpleNamedBean.class.getName();

        // Before JENKINS-50470 fix, this would error out on "unclassified field java.util.ArrayList name"
        assertEvaluate(new AnnotatedWhitelist(), Arrays.asList("a", "b", "c"),
                "def l = [new " + snb + "('a'), new " + snb +"('b'), new " + snb + "('c')]\n" +
                        "return l.name\n");

        // We should still be calling checkedGetProperty properly for the objects within the collection.
        assertRejected(new AnnotatedWhitelist(), "method org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxInterceptorTest$SimpleNamedBean getOther",
                "def l = [new " + snb + "('a'), new " + snb +"('b'), new " + snb + "('c')]\n" +
                        "return l.other\n");
    }

    @Issue("JENKINS-50843")
    @Test
    public void callClosureElementOfMapAsMethod() throws Exception {
        assertEvaluate(new GenericWhitelist(), "hello", "def m = [ f: {return 'hello'} ]; m.f()");
        assertEvaluate(new GenericWhitelist(), 15, "def m = [ f: {a -> return a*3} ]; m.f(5)");
        assertEvaluate(new GenericWhitelist(), "a=hello,b=10", "def m = [ f: {a,b -> return \"a=${a},b=${b}\"} ]; m.f('hello',10)");
        assertEvaluate(new GenericWhitelist(), 2, "def m = [ f: {it.size()} ]; m.f(foo:0, bar:1)");
    }

    @Issue("JENKINS-50906")
    @Test
    public void scriptBindingClosureVariableCall() throws Exception {
        assertEvaluate(new GenericWhitelist(), true, "def func = { 1 }; this.func2 = { 1 }; return func() == func2();\n");
        assertEvaluate(new GenericWhitelist(), true, "def func = { x -> x }; this.func2 = { x -> x }; return func(5) == func2(5);\n");
        assertEvaluate(new GenericWhitelist(), true, "def func = { x, y -> x * y }; this.func2 = { x, y -> x * y }; return func(4, 5) == func2(4, 5);\n");
        assertEvaluate(new GenericWhitelist(), true, "def func = { it }; this.func2 = { it }; return func(12) == func2(12);\n");
    }

    @Test
    public void dateTimeApi() throws Exception {
        assertEvaluate(new GenericWhitelist(), 8, "def tomorrow = java.time.LocalDate.now().plusDays(1).format(java.time.format.DateTimeFormatter.BASIC_ISO_DATE).length()");
        assertEvaluate(new GenericWhitelist(), "2017-01-06", "def yesterday = java.time.LocalDate.parse('2017-01-07').minusDays(1).format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE)");
        assertEvaluate(new GenericWhitelist(), 15, "java.time.LocalTime.now().withHour(15).getHour()");
        assertEvaluate(new GenericWhitelist(), "20:42:00", "java.time.LocalTime.parse('23:42').minusHours(3).format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME)");
        assertEvaluate(new GenericWhitelist(), 15, "java.time.LocalDateTime.now().withMinute(15).minute");
        assertEvaluate(new GenericWhitelist(), "2007-12-03T07:15:30", "java.time.LocalDateTime.parse('2007-12-03T10:15:30').minusHours(3).format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)");
    }

    @Issue("SECURITY-1186")
    @Test
    public void finalizer() throws Exception {
        try {
            evaluate(new GenericWhitelist(), "class Test { public void finalize() { } }; null");
            fail("Finalizers should be rejected");
        } catch (MultipleCompilationErrorsException e) {
            assertThat(e.getErrorCollector().getErrorCount(), equalTo(1));
            Exception innerE = e.getErrorCollector().getException(0);
            assertThat(innerE, instanceOf(SecurityException.class));
            assertThat(innerE.getMessage(), containsString("Object.finalize()"));
        }
    }

}
