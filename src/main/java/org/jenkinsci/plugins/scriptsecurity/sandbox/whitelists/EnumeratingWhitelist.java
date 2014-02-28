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

package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import java.util.Arrays;
import java.util.List;

/**
 * A whitelist based on listing signatures and searching them.
 */
public abstract class EnumeratingWhitelist extends Whitelist {

    protected abstract List<MethodSignature> methodSignatures();

    protected abstract List<NewSignature> newSignatures();

    protected abstract List<StaticMethodSignature> staticMethodSignatures();

    protected abstract List<FieldSignature> fieldSignatures();

    // TODO should cache hits based on concrete types

    @Override public final boolean permitsMethod(Object receiver, String method, Object[] args) {
        for (MethodSignature s : methodSignatures()) {
            if (s.is(receiver, method, args)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsNew(Class<?> receiver, Object[] args) {
        for (NewSignature s : newSignatures()) {
            if (s.is(receiver, args)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticMethod(Class<?> receiver, String method, Object[] args) {
        for (StaticMethodSignature s : staticMethodSignatures()) {
            if (s.is(receiver, method, args)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldGet(Object receiver, String field) {
        for (FieldSignature s : fieldSignatures()) {
            if (s.is(receiver, field)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldSet(Object receiver, String field, Object value) {
        for (FieldSignature s : fieldSignatures()) {
            if (s.is(receiver, field)) {
                return true;
            }
        }
        return false;
    }

    private static boolean is(String type, Object arg) {
        if (arg == null) {
            return true;
        } else {
            return is(type, arg.getClass());
        }
    }

    private static boolean is(String type, Class<?> c) {
        if (getName(c).equals(type)) {
            return true;
        }
        Class<?> supe = c.getSuperclass();
        if (supe != null && is(type, supe)) {
            return true;
        }
        for (Class<?> xface : c.getInterfaces()) {
            if (is(type, xface)) {
                return true;
            }
        }
        Class<?> componentType = c.getComponentType();
        if (componentType != null && type.endsWith("[]") && is(type.substring(0, type.length() - 2), componentType)) {
            return true;
        }
        return false;
    }

    private static boolean is(String[] types, Object[] args) {
        if (args.length != types.length) {
            return false;
        }
        for (int i = 0; i < types.length; i++) {
            if (!is(types[i], args[i])) {
                return false;
            }
        }
        return true;
    }

    private static boolean is(String thisIdentifier, String identifier) {
        return thisIdentifier.equals("*") || identifier.equals(thisIdentifier);
    }

    static String getName(Class<?> c) {
        Class<?> e = c.getComponentType();
        if (e == null) {
            return c.getName();
        } else {
            return getName(e) + "[]";
        }
    }

    private static String[] argumentTypes(Class<?>[] argumentTypes) {
        String[] s = new String[argumentTypes.length];
        for (int i = 0; i < argumentTypes.length; i++) {
            s[i] = getName(argumentTypes[i]);
        }
        return s;
    }

    static final class MethodSignature {
        private final String receiverType, method;
        private final String[] argumentTypes;
        MethodSignature(String receiverType, String method, String[] argumentTypes) {
            this.receiverType = receiverType;
            this.method = method;
            this.argumentTypes = argumentTypes.clone();
        }
        MethodSignature(Class<?> receiverType, String method, Class<?>... argumentTypes) {
            this(getName(receiverType), method, argumentTypes(argumentTypes));
        }
        boolean is(Object receiver, String method, Object[] args) {
            return EnumeratingWhitelist.is(this.method, method) && EnumeratingWhitelist.is(receiverType, receiver) && EnumeratingWhitelist.is(argumentTypes, args);
        }
        @Override public String toString() {
            // TODO should perhaps use this from StaticWhitelist.methodDefinition (or even return a MethodSignature directly?):
            return receiverType + "." + method + Arrays.toString(argumentTypes);
        }
    }

    static final class NewSignature {
        private final String type;
        private final String[] argumentTypes;
        NewSignature(String type, String[] argumentTypes) {
            this.type = type;
            this.argumentTypes = argumentTypes.clone();
        }
        NewSignature(Class<?> type, Class<?>... argumentTypes) {
            this(getName(type), argumentTypes(argumentTypes));
        }
        boolean is(Class<?> receiver, Object[] args) {
            return EnumeratingWhitelist.is(type, receiver) && EnumeratingWhitelist.is(argumentTypes, args);
        }
    }

    static final class StaticMethodSignature {
        private final String receiverType, method;
        private final String[] argumentTypes;
        StaticMethodSignature(String receiverType, String method, String[] argumentTypes) {
            this.receiverType = receiverType;
            this.method = method;
            this.argumentTypes = argumentTypes.clone();
        }
        StaticMethodSignature(Class<?> receiverType, String method, Class<?>... argumentTypes) {
            this(getName(receiverType), method, argumentTypes(argumentTypes));
        }
        boolean is(Class<?> receiver, String method, Object[] args) {
            return EnumeratingWhitelist.is(this.method, method) && EnumeratingWhitelist.is(receiverType, receiver) && EnumeratingWhitelist.is(argumentTypes, args);
        }
    }

    static final class FieldSignature {
        private final String type, field;
        FieldSignature(String type, String field) {
            this.type = type;
            this.field = field;
        }
        FieldSignature(Class<?> type, String field) {
            this(getName(type), field);
        }
        boolean is(Object receiver, String field) {
            return EnumeratingWhitelist.is(this.field, field) && EnumeratingWhitelist.is(type, receiver);
        }
    }

}
