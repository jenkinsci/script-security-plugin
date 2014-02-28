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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.CheckForNull;

/**
 * Whitelist based on a static file.
 */
public final class StaticWhitelist extends EnumeratingWhitelist {

    final List<MethodSignature> methodSignatures = new ArrayList<MethodSignature>();
    final List<NewSignature> newSignatures = new ArrayList<NewSignature>();
    final List<StaticMethodSignature> staticMethodSignatures = new ArrayList<StaticMethodSignature>();
    final List<FieldSignature> fieldSignatures = new ArrayList<FieldSignature>();

    public StaticWhitelist(Reader definition) throws IOException {
        BufferedReader br = new BufferedReader(definition);
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.length() == 0 || line.startsWith("#")) {
                continue;
            }
            add(line);
        }
    }

    public StaticWhitelist(Collection<? extends String> lines) throws IOException {
        for (String line : lines) {
            add(line);
        }
    }

    private void add(String line) throws IOException {
        String[] toks = line.split(" ");
        if (toks[0].equals("method")) {
            if (toks.length < 3) {
                throw new IOException(line);
            }
            methodSignatures.add(new MethodSignature(toks[1], toks[2], slice(toks, 3)));
        } else if (toks[0].equals("new")) {
            if (toks.length < 2) {
                throw new IOException(line);
            }
            newSignatures.add(new NewSignature(toks[1], slice(toks, 2)));
        } else if (toks[0].equals("staticMethod")) {
            if (toks.length < 3) {
                throw new IOException(line);
            }
            staticMethodSignatures.add(new StaticMethodSignature(toks[1], toks[2], slice(toks, 3)));
        } else if (toks[0].equals("field")) {
            if (toks.length != 3) {
                throw new IOException(line);
            }
            fieldSignatures.add(new FieldSignature(toks[1], toks[2]));
        } else {
            throw new IOException(line);
        }
    }

    private static String[] slice(String[] toks, int from) {
        // TODO Java 6: return Arrays.copyOfRange(toks, from, toks.length);
        String[] r = new String[toks.length - from];
        System.arraycopy(toks, from, r, 0, toks.length - from);
        return r;
    }

    public static Whitelist from(URL definition) throws IOException {
        InputStream is = definition.openStream();
        try {
            return new StaticWhitelist(new InputStreamReader(is, "UTF-8"));
        } finally {
            is.close();
        }
    }

    @Override protected List<MethodSignature> methodSignatures() {
        return methodSignatures;
    }

    @Override protected List<NewSignature> newSignatures() {
        return newSignatures;
    }

    @Override protected List<StaticMethodSignature> staticMethodSignatures() {
        return staticMethodSignatures;
    }

    @Override protected List<FieldSignature> fieldSignatures() {
        return fieldSignatures;
    }

    private static boolean matches(Class<?>[] parameterTypes, Object[] parameters) {
        if (parameters.length != parameterTypes.length) {
            return false;
        }
        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameters[i] != null && !parameterTypes[i].isInstance(parameters[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Looks up the most general possible definition of a given method call.
     * Preferentially searches for compatible definitions in supertypes.
     * The result (if not null) may be added to a static whitelist after the keyword {@code method}.
     * @param receiver an actual receiver object
     * @param method the method name
     * @param args a set of actual arguments
     * @return a definition in the format {@code receiver.class.Name methodName parameter1.Type parameter2.Type}, or null if not found
     */
    public static @CheckForNull String methodDefinition(Object receiver, String method, Object[] args) {
        for (Class<?> c : types(receiver)) {
            for (Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals(method)) {
                    continue;
                }
                Class<?>[] parameterTypes = m.getParameterTypes();
                if (matches(parameterTypes, args)) {
                    return getName(c) + " " + method + printArgumentTypes(parameterTypes);
                }
            }
        }
        return null;
    }

    public static @CheckForNull String newDefinition(Class<?> receiver, Object[] args) {
        for (Constructor<?> c : receiver.getDeclaredConstructors()) {
            Class<?>[] parameterTypes = c.getParameterTypes();
            if (matches(parameterTypes, args)) {
                return c.getName() + printArgumentTypes(parameterTypes);
            }
        }
        return null;
    }

    public static @CheckForNull String staticMethodDefinition(Class<?> receiver, String method, Object[] args) {
        // TODO should we check for inherited static calls?
        for (Method m : receiver.getDeclaredMethods()) {
            if (!m.getName().equals(method)) {
                continue;
            }
            Class<?>[] parameterTypes = m.getParameterTypes();
            if (matches(parameterTypes, args)) {
                return getName(receiver) + " " + method + printArgumentTypes(parameterTypes);
            }
        }
        return null;
    }

    public static @CheckForNull String fieldDefinition(Object receiver, String field) {
        for (Class<?> c : types(receiver)) {
            for (Field f : c.getDeclaredFields()) {
                if (!f.getName().equals(field)) {
                    continue;
                }
                return getName(c) + " " + field;
            }
        }
        return null;
    }

    private static Iterable<Class<?>> types(Object o) {
        Set<Class<?>> types = new LinkedHashSet<Class<?>>();
        visitTypes(types, o.getClass());
        return types;
    }
    private static void visitTypes(Set<Class<?>> types, Class<?> c) {
        Class<?> s = c.getSuperclass();
        if (s != null) {
            visitTypes(types, s);
        }
        for (Class<?> i : c.getInterfaces()) {
            visitTypes(types, i);
        }
        // Visit supertypes first.
        types.add(c);
    }

    private static String printArgumentTypes(Class<?>[] parameterTypes) {
        StringBuilder b = new StringBuilder();
        for (Class<?> c : parameterTypes) {
            b.append(' ');
            b.append(getName(c));
        }
        return b.toString();
    }

}
