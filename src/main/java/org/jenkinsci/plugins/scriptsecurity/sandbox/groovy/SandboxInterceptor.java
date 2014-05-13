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

import groovy.lang.Script;
import hudson.Functions;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.kohsuke.groovy.sandbox.GroovyInterceptor;

@SuppressWarnings("rawtypes")
final class SandboxInterceptor extends GroovyInterceptor {

    private final Whitelist whitelist;
    
    SandboxInterceptor(Whitelist whitelist) {
        this.whitelist = whitelist;
    }

    @Override public Object onMethodCall(GroovyInterceptor.Invoker invoker, Object receiver, String method, Object... args) throws Throwable {
        Method m = GroovyCallSiteSelector.method(receiver, method, args);
        if (m == null) {
            if (receiver instanceof Number || (receiver instanceof String && method.equals("plus"))) {
                // Synthetic methods like Integer.plus(Integer).
                return super.onMethodCall(invoker, receiver, method, args);
            } else {
                throw new RejectedAccessException("unclassified method " + EnumeratingWhitelist.getName(receiver.getClass()) + " " + method + printArgumentTypes(args));
            }
        } else if (whitelist.permitsMethod(m, receiver, args)) {
            return super.onMethodCall(invoker, receiver, method, args);
        } else {
            throw StaticWhitelist.rejectMethod(m);
        }
    }

    @Override public Object onNewInstance(GroovyInterceptor.Invoker invoker, Class receiver, Object... args) throws Throwable {
        Constructor<?> c = GroovyCallSiteSelector.constructor(receiver, args);
        if (c == null) {
            throw new RejectedAccessException("unclassified new " + EnumeratingWhitelist.getName(receiver) + printArgumentTypes(args));
        } else if (whitelist.permitsConstructor(c, args)) {
            return super.onNewInstance(invoker, receiver, args);
        } else {
            throw StaticWhitelist.rejectNew(c);
        }
    }

    @Override public Object onStaticCall(GroovyInterceptor.Invoker invoker, Class receiver, String method, Object... args) throws Throwable {
        Method m = GroovyCallSiteSelector.staticMethod(receiver, method, args);
        if (m == null) {
            throw new RejectedAccessException("unclassified staticMethod " + EnumeratingWhitelist.getName(receiver) + " " + method + printArgumentTypes(args));
        } else if (whitelist.permitsStaticMethod(m, args)) {
            return super.onStaticCall(invoker, receiver, method, args);
        } else {
            throw StaticWhitelist.rejectStaticMethod(m);
        }
    }

    @edu.umd.cs.findbugs.annotations.SuppressWarnings("NP_LOAD_OF_KNOWN_NULL_VALUE")
    @Override public Object onSetProperty(GroovyInterceptor.Invoker invoker, Object receiver, String property, Object value) throws Throwable {
        if (receiver == null) {
            // TODO https://github.com/kohsuke/groovy-sandbox/issues/15 should not be necessary
            return super.onSetProperty(invoker, receiver, property, value);
        }
        Field f = GroovyCallSiteSelector.field(receiver, property);
        if (f != null && whitelist.permitsFieldSet(f, receiver, value)) {
            return super.onSetProperty(invoker, receiver, property, value);
        }
        // https://github.com/kohsuke/groovy-sandbox/issues/7 need to explicitly check for getters and setters:
        Object[] args = new Object[] {value};
        Method m = GroovyCallSiteSelector.method(receiver, "set" + Functions.capitalize(property), args);
        if (m != null && whitelist.permitsMethod(m, receiver, args)) {
            return super.onSetProperty(invoker, receiver, property, value);
        }
        args = new Object[] {property, value};
        Method m2 = GroovyCallSiteSelector.method(receiver, "setProperty", args);
        if (m2 != null && whitelist.permitsMethod(m2, receiver, args)) {
            return super.onSetProperty(invoker, receiver, property, value);
        }
        Field f2 = null;
        if (receiver instanceof Class) {
            f2 = GroovyCallSiteSelector.staticField((Class) receiver, property);
            if (f2 != null && whitelist.permitsStaticFieldSet(f2, value)) {
                return super.onSetProperty(invoker, receiver, property, value);
            }
        }
        throw rejectField(f, m, m2, f2, receiver, property);
    }

    @edu.umd.cs.findbugs.annotations.SuppressWarnings("NP_LOAD_OF_KNOWN_NULL_VALUE")
    @Override public Object onGetProperty(GroovyInterceptor.Invoker invoker, Object receiver, String property) throws Throwable {
        if (receiver == null) {
            // TODO https://github.com/kohsuke/groovy-sandbox/issues/15 should not be necessary
            return super.onGetProperty(invoker, receiver, property);
        }
        if (receiver instanceof Script && property.equals("out")) { // cf. SimpleTemplateEngine
            return super.onGetProperty(invoker, receiver, property);
        }
        if (property.equals("length") && receiver.getClass().isArray()) {
            return super.onGetProperty(invoker, receiver, property);
        }
        Field f = GroovyCallSiteSelector.field(receiver, property);
        if (f != null && whitelist.permitsFieldGet(f, receiver)) {
            return super.onGetProperty(invoker, receiver, property);
        }
        Object[] args = new Object[] {};
        Method m = GroovyCallSiteSelector.method(receiver, "get" + Functions.capitalize(property), args);
        if (m != null && whitelist.permitsMethod(m, receiver, args)) {
            return super.onGetProperty(invoker, receiver, property);
        }
        args = new Object[] {property};
        Method m2 = GroovyCallSiteSelector.method(receiver, "getProperty", args);
        if (m2 != null && whitelist.permitsMethod(m2, receiver, args)) {
            return super.onGetProperty(invoker, receiver, property);
        }
        Field f2 = null;
        if (receiver instanceof Class) {
            f2 = GroovyCallSiteSelector.staticField((Class) receiver, property);
            if (f2 != null && whitelist.permitsStaticFieldGet(f2)) {
                return super.onGetProperty(invoker, receiver, property);
            }
        }
        throw rejectField(f, m, m2, f2, receiver, property);
    }

    private static RejectedAccessException rejectField(Field f, Method m, Method m2, Field f2, Object receiver, String property) {
        if (f == null) {
            if (m == null) {
                if (m2 == null) {
                    if (f2 == null) {
                        return new RejectedAccessException("unclassified field " + EnumeratingWhitelist.getName(receiver.getClass()) + " " + property);
                    } else {
                        return StaticWhitelist.rejectStaticField(f2);
                    }
                } else {
                    return StaticWhitelist.rejectMethod(m2);
                }
            } else {
                return StaticWhitelist.rejectMethod(m);
            }
        } else {
            // TODO consider using rejectMethod (for non-null m), especially if the field is not public
            return StaticWhitelist.rejectField(f);
        }
    }

    // TODO consider whether it is useful to override onGet/SetArray/Attribute

    private static String printArgumentTypes(Object[] args) {
        StringBuilder b = new StringBuilder();
        for (Object arg : args) {
            b.append(' ');
            b.append(arg == null ? "null" : EnumeratingWhitelist.getName(arg.getClass()));
        }
        return b.toString();
    }

}
