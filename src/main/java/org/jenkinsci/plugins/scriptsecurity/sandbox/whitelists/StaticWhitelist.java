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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Whitelist based on a static file.
 */
public final class StaticWhitelist extends EnumeratingWhitelist {
    private static final String[] PERMANENTLY_BLACKLISTED_METHODS = {
            "method java.lang.Runtime exit int",
            "method java.lang.Runtime halt int",
    };

    private static final String[] PERMANENTLY_BLACKLISTED_STATIC_METHODS = {
            "staticMethod java.lang.System exit int",
    };

    private static final String[] PERMANENTLY_BLACKLISTED_CONSTRUCTORS = {
            "new org.kohsuke.groovy.sandbox.impl.Checker$SuperConstructorWrapper java.lang.Object[]",
            "new org.kohsuke.groovy.sandbox.impl.Checker$ThisConstructorWrapper java.lang.Object[]"
    };

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
    static @CheckForNull String filter(@Nonnull String line) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return null;
        }
        return line;
    }

    /**
     * Returns true if the given method is permanently blacklisted in {@link #PERMANENTLY_BLACKLISTED_METHODS}
     */
    public static boolean isPermanentlyBlacklistedMethod(@Nonnull Method m) {
        String signature = canonicalMethodSig(m);

        for (String s : PERMANENTLY_BLACKLISTED_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true if the given method is permanently blacklisted in {@link #PERMANENTLY_BLACKLISTED_STATIC_METHODS}
     */
    public static boolean isPermanentlyBlacklistedStaticMethod(@Nonnull Method m) {
        String signature = canonicalStaticMethodSig(m);

        for (String s : PERMANENTLY_BLACKLISTED_STATIC_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true if the given constructor is permanently blacklisted in {@link #PERMANENTLY_BLACKLISTED_CONSTRUCTORS}
     */
    public static boolean isPermanentlyBlacklistedConstructor(@Nonnull Constructor c) {
        String signature = canonicalConstructorSig(c);

        for (String s : PERMANENTLY_BLACKLISTED_CONSTRUCTORS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse a signature line into a {@link Signature}.
     * @param line The signature string
     * @return the equivalent {@link Signature}
     * @throws IOException if the signature string could not be parsed.
     */
    public static Signature parse(String line) throws IOException {
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
            throw new IOException("Malformed signature entry: '" + line + "'");
        }
    }

    /**
     * Checks if the signature is permanently blacklisted, and so shouldn't show up in the pending approval list.
     * @param signature the signature to check
     * @return true if the signature is permanently blacklisted, false otherwise.
     */
    public static boolean isPermanentlyBlacklisted(String signature) {
        for (String s : PERMANENTLY_BLACKLISTED_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }
        for (String s : PERMANENTLY_BLACKLISTED_STATIC_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }
        for (String s : PERMANENTLY_BLACKLISTED_CONSTRUCTORS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
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
        ScriptApproval.maybeRegister(x);
        return x;
    }

    @Restricted(NoExternalUse.class) // ScriptApproval
    public static boolean isBlacklisted(String signature) {
        return BLACKLIST.contains(signature);
    }

}
