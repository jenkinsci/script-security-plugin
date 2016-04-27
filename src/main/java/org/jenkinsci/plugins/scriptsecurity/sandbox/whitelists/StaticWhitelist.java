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
import static java.util.Arrays.asList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.GroovySystem;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;

/**
 * Whitelist based on a static file.
 */
public final class StaticWhitelist extends EnumeratingWhitelist {
    private static final String G2_PREFIX = "g2";
    private static final boolean GROOVY2 = GroovySystem.getVersion().startsWith("2.");

    final List<MethodSignature> methodSignatures = new ArrayList<MethodSignature>();
    final List<NewSignature> newSignatures = new ArrayList<NewSignature>();
    final List<MethodSignature> staticMethodSignatures = new ArrayList<MethodSignature>();
    final List<FieldSignature> fieldSignatures = new ArrayList<FieldSignature>();
    final List<FieldSignature> staticFieldSignatures = new ArrayList<FieldSignature>();

    public StaticWhitelist(Reader definition) throws IOException {
        BufferedReader br = new BufferedReader(definition);
        String line;
        while ((line = br.readLine()) != null) {
            line = filter(line);
            if (line != null) {
                add(line);
            }
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

    /**
     * Filters a line, returning the content that must be processed.
     * @param line Line to filter.
     * @return {@code null} if the like must be skipped or the content to process if not.
     */
    static String filter(String line) {
        if (line == null) {
            return null;
        }
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return null;
        }
        if (line.startsWith(G2_PREFIX)) {
            if (GROOVY2) {
                return line.substring(G2_PREFIX.length()).trim();
                // If empty or malformed after the prefix, we'll leave the parsing fail.
            } else {
                return null; // skip
            }
        }
        return line;
    }

    static Signature parse(String line) throws IOException {
        String[] toks = line.split(" ");
        if (toks[0].equals("method")) {
            if (toks.length < 3) {
                throw new IOException(line);
            }
            return new MethodSignature(toks[1], toks[2], Arrays.copyOfRange(toks, 3, toks.length));
        } else if (toks[0].equals("new")) {
            if (toks.length < 2) {
                throw new IOException(line);
            }
            return new NewSignature(toks[1], Arrays.copyOfRange(toks, 2, toks.length));
        } else if (toks[0].equals("staticMethod")) {
            if (toks.length < 3) {
                throw new IOException(line);
            }
            return new StaticMethodSignature(toks[1], toks[2], Arrays.copyOfRange(toks, 3, toks.length));
        } else if (toks[0].equals("field")) {
            if (toks.length != 3) {
                throw new IOException(line);
            }
            return new FieldSignature(toks[1], toks[2]);
        } else if (toks[0].equals("staticField")) {
            if (toks.length != 3) {
                throw new IOException(line);
            }
            return new StaticFieldSignature(toks[1], toks[2]);
        } else {
            throw new IOException(line);
        }
    }

    private void add(String line) throws IOException {
        Signature s = parse(line);
        if (s instanceof StaticMethodSignature) {
            staticMethodSignatures.add((StaticMethodSignature) s);
        } else if (s instanceof MethodSignature) {
            methodSignatures.add((MethodSignature) s);
        } else if (s instanceof StaticFieldSignature) {
            staticFieldSignatures.add((StaticFieldSignature) s);
        } else if (s instanceof FieldSignature) {
            fieldSignatures.add((FieldSignature) s);
        } else {
            newSignatures.add((NewSignature) s);
        }
    }

    public static StaticWhitelist from(URL definition) throws IOException {
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
        return blacklist(new RejectedAccessException("method", EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName() + printArgumentTypes(m.getParameterTypes())));
    }

    public static RejectedAccessException rejectMethod(@Nonnull Method m, String info) {
        assert (m.getModifiers() & Modifier.STATIC) == 0;
        return blacklist(new RejectedAccessException("method", EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName() + printArgumentTypes(m.getParameterTypes()), info));
    }

    public static RejectedAccessException rejectNew(@Nonnull Constructor<?> c) {
        return blacklist(new RejectedAccessException("new", EnumeratingWhitelist.getName(c.getDeclaringClass()) + printArgumentTypes(c.getParameterTypes())));
    }

    public static RejectedAccessException rejectStaticMethod(@Nonnull Method m) {
        assert (m.getModifiers() & Modifier.STATIC) != 0;
        return blacklist(new RejectedAccessException("staticMethod", EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName() + printArgumentTypes(m.getParameterTypes())));
    }

    public static RejectedAccessException rejectField(@Nonnull Field f) {
        assert (f.getModifiers() & Modifier.STATIC) == 0;
        return blacklist(new RejectedAccessException("field", EnumeratingWhitelist.getName(f.getDeclaringClass()) + " " + f.getName()));
    }

    public static RejectedAccessException rejectStaticField(@Nonnull Field f) {
        assert (f.getModifiers() & Modifier.STATIC) != 0;
        return blacklist(new RejectedAccessException("staticField", EnumeratingWhitelist.getName(f.getDeclaringClass()) + " " + f.getName()));
    }

    private static String printArgumentTypes(Class<?>[] parameterTypes) {
        StringBuilder b = new StringBuilder();
        for (Class<?> c : parameterTypes) {
            b.append(' ');
            b.append(EnumeratingWhitelist.getName(c));
        }
        return b.toString();
    }

    private static final Set<String> BLACKLIST;

    @SuppressFBWarnings(value = "OS_OPEN_STREAM", justification = "https://sourceforge.net/p/findbugs/bugs/786/")
    private static Set<String> loadBlacklist() throws IOException {
        InputStream is = StaticWhitelist.class.getResourceAsStream("blacklist");
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "US-ASCII"));
            Set<String> blacklist = new HashSet<String>();
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                // TODO could consider trying to load the AccessibleObject, assuming the defining Class is accessible, as a defense against typos
                blacklist.add(line);
            }
            return blacklist;
        } finally {
            is.close();
        }
    }

    static {
        try {
            BLACKLIST = loadBlacklist();
        } catch (IOException x) {
            throw new ExceptionInInitializerError(x);
        }
    }

    private static RejectedAccessException blacklist(RejectedAccessException x) {
        if (BLACKLIST.contains(x.getSignature())) {
            x.setDangerous(true);
        }
        return x;
    }

}
