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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

/**
 * A whitelist based on listing signatures and searching them.
 */
public abstract class EnumeratingWhitelist extends Whitelist {

    protected abstract List<MethodSignature> methodSignatures();

    protected abstract List<NewSignature> newSignatures();

    protected abstract List<MethodSignature> staticMethodSignatures();

    protected abstract List<FieldSignature> fieldSignatures();

    // TODO should precompute hash sets of signatures, assuming we document that the signatures may not change over the lifetime of the whitelist (or pass them in the constructor)

    @Override public final boolean permitsMethod(Method method, Object receiver, Object[] args) {
        for (MethodSignature s : methodSignatures()) {
            if (s.matches(method)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsConstructor(Constructor<?> constructor, Object[] args) {
        for (NewSignature s : newSignatures()) {
            if (s.matches(constructor)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticMethod(Method method, Object[] args) {
        for (MethodSignature s : staticMethodSignatures()) {
            if (s.matches(method)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldGet(Field field, Object receiver) {
        for (FieldSignature s : fieldSignatures()) {
            if (s.matches(field)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldSet(Field field, Object receiver, Object value) {
        for (FieldSignature s : fieldSignatures()) {
            if (s.matches(field)) {
                return true;
            }
        }
        return false;
    }

    public static String getName(Class<?> c) {
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

    private static boolean is(String thisIdentifier, String identifier) {
        return thisIdentifier.equals("*") || identifier.equals(thisIdentifier);
    }

    public static final class MethodSignature {
        private final String receiverType, method;
        private final String[] argumentTypes;
        public MethodSignature(String receiverType, String method, String[] argumentTypes) {
            this.receiverType = receiverType;
            this.method = method;
            this.argumentTypes = argumentTypes.clone();
        }
        public MethodSignature(Class<?> receiverType, String method, Class<?>... argumentTypes) {
            this(getName(receiverType), method, argumentTypes(argumentTypes));
        }
        @Override public String toString() {
            return receiverType + "." + method + Arrays.toString(argumentTypes);
        }
        boolean matches(Method m) {
            return is(method, m.getName()) && getName(m.getDeclaringClass()).equals(receiverType) && Arrays.equals(argumentTypes(m.getParameterTypes()), argumentTypes);
        }
    }

    public static final class NewSignature {
        private final String type;
        private final String[] argumentTypes;
        public NewSignature(String type, String[] argumentTypes) {
            this.type = type;
            this.argumentTypes = argumentTypes.clone();
        }
        public NewSignature(Class<?> type, Class<?>... argumentTypes) {
            this(getName(type), argumentTypes(argumentTypes));
        }
        boolean matches(Constructor c) {
            return getName(c.getDeclaringClass()).equals(type) && Arrays.equals(argumentTypes(c.getParameterTypes()), argumentTypes);
        }
    }

    public static final class FieldSignature {
        private final String type, field;
        public FieldSignature(String type, String field) {
            this.type = type;
            this.field = field;
        }
        public FieldSignature(Class<?> type, String field) {
            this(getName(type), field);
        }
        boolean matches(Field f) {
            return is(field, f.getName()) && getName(f.getDeclaringClass()).equals(type);
        }
    }

}
