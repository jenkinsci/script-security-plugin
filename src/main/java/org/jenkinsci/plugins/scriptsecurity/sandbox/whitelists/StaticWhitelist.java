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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

import static java.util.Arrays.asList;

/**
 * Whitelist based on a static file.
 */
public final class StaticWhitelist extends EnumeratingWhitelist {

    final List<MethodSignature> methodSignatures = new ArrayList<MethodSignature>();
    final List<NewSignature> newSignatures = new ArrayList<NewSignature>();
    final List<MethodSignature> staticMethodSignatures = new ArrayList<MethodSignature>();
    final List<FieldSignature> fieldSignatures = new ArrayList<FieldSignature>();
    final List<FieldSignature> staticFieldSignatures = new ArrayList<FieldSignature>();

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

    public StaticWhitelist(String... lines) throws IOException {
        this(asList(lines));
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
            staticMethodSignatures.add(new MethodSignature(toks[1], toks[2], slice(toks, 3)));
        } else if (toks[0].equals("field")) {
            if (toks.length != 3) {
                throw new IOException(line);
            }
            fieldSignatures.add(new FieldSignature(toks[1], toks[2]));
        } else if (toks[0].equals("staticField")) {
            if (toks.length != 3) {
                throw new IOException(line);
            }
            staticFieldSignatures.add(new FieldSignature(toks[1], toks[2]));
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

    @Override protected List<MethodSignature> staticMethodSignatures() {
        return staticMethodSignatures;
    }

    @Override protected List<FieldSignature> fieldSignatures() {
        return fieldSignatures;
    }

    @Override protected List<FieldSignature> staticFieldSignatures() {
        return staticFieldSignatures;
    }

    public static RejectedAccessException rejectMethod(@Nonnull Method m) {
        assert (m.getModifiers() & Modifier.STATIC) == 0;
        return new RejectedAccessException("method", EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName() + printArgumentTypes(m.getParameterTypes()));
    }

    public static RejectedAccessException rejectMethod(@Nonnull Method m, String info) {
        assert (m.getModifiers() & Modifier.STATIC) == 0;
        return new RejectedAccessException("method", EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName() + printArgumentTypes(m.getParameterTypes()), info);
    }

    public static RejectedAccessException rejectNew(@Nonnull Constructor<?> c) {
        return new RejectedAccessException("new", EnumeratingWhitelist.getName(c.getDeclaringClass()) + printArgumentTypes(c.getParameterTypes()));
    }

    public static RejectedAccessException rejectStaticMethod(@Nonnull Method m) {
        assert (m.getModifiers() & Modifier.STATIC) != 0;
        return new RejectedAccessException("staticMethod", EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName() + printArgumentTypes(m.getParameterTypes()));
    }

    public static RejectedAccessException rejectField(@Nonnull Field f) {
        assert (f.getModifiers() & Modifier.STATIC) == 0;
        return new RejectedAccessException("field", EnumeratingWhitelist.getName(f.getDeclaringClass()) + " " + f.getName());
    }

    public static RejectedAccessException rejectStaticField(@Nonnull Field f) {
        assert (f.getModifiers() & Modifier.STATIC) != 0;
        return new RejectedAccessException("staticField", EnumeratingWhitelist.getName(f.getDeclaringClass()) + " " + f.getName());
    }

    private static String printArgumentTypes(Class<?>[] parameterTypes) {
        StringBuilder b = new StringBuilder();
        for (Class<?> c : parameterTypes) {
            b.append(' ');
            b.append(EnumeratingWhitelist.getName(c));
        }
        return b.toString();
    }

}
