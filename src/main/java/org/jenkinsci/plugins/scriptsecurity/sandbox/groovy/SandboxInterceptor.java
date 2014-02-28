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
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import hudson.Functions;
import org.kohsuke.groovy.sandbox.GroovyInterceptor;

@SuppressWarnings("rawtypes")
final class SandboxInterceptor extends GroovyInterceptor {

    private final Whitelist whitelist;
    
    SandboxInterceptor(Whitelist whitelist) {
        this.whitelist = whitelist;
    }

    @Override public Object onMethodCall(GroovyInterceptor.Invoker invoker, Object receiver, String method, Object... args) throws Throwable {
        args = fixGStrings(args);
        if (whitelist.permitsMethod(receiver, method, args)) {
            return super.onMethodCall(invoker, receiver, method, args);
        } else {
            String def = StaticWhitelist.methodDefinition(receiver, method, args);
            if (def != null) {
                throw new RejectedAccessException("method", def);
            } else {
                throw new RejectedAccessException("unclassified method " + receiver.getClass().getName() + " " + method + printArgumentTypes(args));
            }
        }
    }

    @Override public Object onNewInstance(GroovyInterceptor.Invoker invoker, Class receiver, Object... args) throws Throwable {
        args = fixGStrings(args);
        if (whitelist.permitsNew(receiver, args)) {
            return super.onNewInstance(invoker, receiver, args);
        } else {
            String def = StaticWhitelist.newDefinition(receiver, args);
            if (def != null) {
                throw new RejectedAccessException("new", def);
            } else {
                throw new RejectedAccessException("unclassified new " + receiver.getName() + printArgumentTypes(args));
            }
        }
    }

    @Override public Object onStaticCall(GroovyInterceptor.Invoker invoker, Class receiver, String method, Object... args) throws Throwable {
        args = fixGStrings(args);
        if (whitelist.permitsStaticMethod(receiver, method, args)) {
            return super.onStaticCall(invoker, receiver, method, args);
        } else {
            String def = StaticWhitelist.staticMethodDefinition(receiver, method, args);
            if (def != null) {
                throw new RejectedAccessException("staticMethod", def);
            } else {
                throw new RejectedAccessException("unclassified staticMethod " + receiver.getName() + " " + method + printArgumentTypes(args));
            }
        }
    }

    @Override public Object onSetProperty(GroovyInterceptor.Invoker invoker, Object receiver, String property, Object value) throws Throwable {
        value = fixGString(value);
        // https://github.com/kohsuke/groovy-sandbox/issues/7 need to explicitly check for getters and setters:
        if (whitelist.permitsFieldGet(receiver, property) || whitelist.permitsMethod(receiver, "set" + Functions.capitalize(property), new Object[] {value})) {
            return super.onSetProperty(invoker, receiver, property, value);
        } else {
            String field = StaticWhitelist.fieldDefinition(receiver, property);
            if (field == null) {
                String method = StaticWhitelist.methodDefinition(receiver, "set" + Functions.capitalize(property), new Object[] {value});
                if (method == null) {
                    throw new RejectedAccessException("unclassified field " + receiver.getClass().getName() + " " + property);
                } else {
                    throw new RejectedAccessException("method", method);
                }
            } else {
                throw new RejectedAccessException("field", field);
            }
        }
    }

    @Override public Object onGetProperty(GroovyInterceptor.Invoker invoker, Object receiver, String property) throws Throwable {
        if (property.equals("length") && receiver.getClass().isArray() ||
                whitelist.permitsFieldGet(receiver, property) ||
                whitelist.permitsMethod(receiver, "get" + Functions.capitalize(property), new Object[0])) {
            return super.onGetProperty(invoker, receiver, property);
        } else {
            String field = StaticWhitelist.fieldDefinition(receiver, property);
            if (field == null) {
                String method = StaticWhitelist.methodDefinition(receiver, "get" + Functions.capitalize(property), new Object[0]);
                if (method == null) {
                    throw new RejectedAccessException("unclassified field " + receiver.getClass().getName() + " " + property);
                } else {
                    throw new RejectedAccessException("method", method);
                }
            } else {
                throw new RejectedAccessException("field", field);
            }
        }
    }

    // TODO consider whether it is useful to override onGet/SetArray/Attribute

    private static String printArgumentTypes(Object[] args) {
        StringBuilder b = new StringBuilder();
        for (Object arg : args) {
            b.append(' ');
            b.append(arg == null ? "null" : arg.getClass().getName());
        }
        return b.toString();
    }

    // TODO this is probably a bug in groovy-sandbox
    private static Object fixGString(Object o) {
        if (o instanceof GString) {
            return o.toString();
        } else {
            return o;
        }
    }
    private static Object[] fixGStrings(Object[] os) {
        Object[] r = new Object[os.length];
        for (int i = 0; i < os.length; i++) {
            r[i] = fixGString(os[i]);
        }
        return r;
    }

}
