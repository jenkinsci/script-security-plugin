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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

import javax.sql.rowset.Predicate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Aggregates several whitelists.
 */
@SuppressFBWarnings(value = "RC_REF_COMPARISON_BAD_PRACTICE_BOOLEAN", justification = "We want to be aware of null Boolean values and reference comparison is very efficient.")
public class ProxyWhitelist extends Whitelist {
    
    private Collection<? extends Whitelist> originalDelegates;
    private final List<Whitelist> delegates = new ArrayList<Whitelist>();
    private final List<Whitelist> sortedDelegates = new ArrayList<Whitelist>();
    private final List<EnumeratingWhitelist.MethodSignature> methodSignatures = new ArrayList<EnumeratingWhitelist.MethodSignature>();
    private final List<EnumeratingWhitelist.NewSignature> newSignatures = new ArrayList<EnumeratingWhitelist.NewSignature>();
    private final List<EnumeratingWhitelist.MethodSignature> staticMethodSignatures = new ArrayList<EnumeratingWhitelist.MethodSignature>();
    private final List<EnumeratingWhitelist.FieldSignature> fieldSignatures = new ArrayList<EnumeratingWhitelist.FieldSignature>();
    private final List<EnumeratingWhitelist.FieldSignature> staticFieldSignatures = new ArrayList<EnumeratingWhitelist.FieldSignature>();
    /** anything wrapping us, so that we can propagate {@link #reset} calls up the chain */
    private final Map<ProxyWhitelist,Void> wrappers = new WeakHashMap<ProxyWhitelist,Void>();

    /** Caches valid permission checks or false if no {@link CacheableWhitelist} approves the entry.
     *  Synchronization not required because we already synchronize on delegates.
     */
    // TODO permission checks look HERE first, then iterate through Whitelists -- if Whitelist approving isinstanceof CacheableWhitelist it is cached.
    // We may also be able to cache notes that none of the CacheableWhitelists match the method so we know to just check dynamic ones and fail if they don't permit
    HashMap<String, Boolean> permittedCache = new HashMap<String, Boolean>();

    public ProxyWhitelist(Collection<? extends Whitelist> delegates) {
        reset(delegates);
    }

    static final Comparator<Whitelist> CACHEABLE_WHITELIST_FIRST = new Comparator<Whitelist>() {
        @Override
        public int compare(Whitelist o1, Whitelist o2) {
            if (o1 instanceof CacheableWhitelist ^ o2 instanceof CacheableWhitelist) {  // If they don't match
                return (o1 instanceof CacheableWhitelist) ? -1 : 1;
            }
            return 0;
        }
    };

    private void reset() {
        reset(originalDelegates);
    }

    public final void reset(Collection<? extends Whitelist> delegates) {
        synchronized (this.delegates) {
            permittedCache.clear();
            originalDelegates = delegates;
            this.delegates.clear();
            methodSignatures.clear();
            newSignatures.clear();
            staticMethodSignatures.clear();
            fieldSignatures.clear();
            this.delegates.add(new EnumeratingWhitelist() {
                @Override protected List<EnumeratingWhitelist.MethodSignature> methodSignatures() {
                    return methodSignatures;
                }
                @Override protected List<EnumeratingWhitelist.NewSignature> newSignatures() {
                    return newSignatures;
                }
                @Override protected List<EnumeratingWhitelist.MethodSignature> staticMethodSignatures() {
                    return staticMethodSignatures;
                }
                @Override protected List<EnumeratingWhitelist.FieldSignature> fieldSignatures() {
                    return fieldSignatures;
                }
                @Override protected List<EnumeratingWhitelist.FieldSignature> staticFieldSignatures() {
                    return staticFieldSignatures;
                }
            });
            for (Whitelist delegate : delegates) {
                if (delegate instanceof EnumeratingWhitelist) {
                    EnumeratingWhitelist ew = (EnumeratingWhitelist) delegate;
                    methodSignatures.addAll(ew.methodSignatures());
                    newSignatures.addAll(ew.newSignatures());
                    staticMethodSignatures.addAll(ew.staticMethodSignatures());
                    fieldSignatures.addAll(ew.fieldSignatures());
                    staticFieldSignatures.addAll(ew.staticFieldSignatures());
                } else if (delegate instanceof ProxyWhitelist) {
                    ProxyWhitelist pw = (ProxyWhitelist) delegate;
                    pw.wrappers.put(this, null);
                    for (Whitelist subdelegate : pw.delegates) {
                        if (subdelegate instanceof EnumeratingWhitelist) {
                            continue; // this is handled specially
                        }
                        this.delegates.add(subdelegate);
                    }
                    methodSignatures.addAll(pw.methodSignatures);
                    newSignatures.addAll(pw.newSignatures);
                    staticMethodSignatures.addAll(pw.staticMethodSignatures);
                    fieldSignatures.addAll(pw.fieldSignatures);
                    staticFieldSignatures.addAll(pw.staticFieldSignatures);
                } else {
                    this.delegates.add(delegate);
                }
            }
            this.sortedDelegates.clear();
            this.sortedDelegates.addAll(this.delegates);
            Collections.sort(this.sortedDelegates, CACHEABLE_WHITELIST_FIRST);
            for (ProxyWhitelist pw : wrappers.keySet()) {
                pw.reset();
            }
        }
    }

    public ProxyWhitelist(Whitelist... delegates) {
        this(Arrays.asList(delegates));
    }

    @Override public final boolean permitsMethod(Method method, Object receiver, Object[] args) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalMethodSig(method);
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsMethod(method, receiver, args)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

    @Override public final boolean permitsConstructor(Constructor<?> constructor, Object[] args) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalConstructorSig(constructor);
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsConstructor(constructor, args)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

    @Override public final boolean permitsStaticMethod(Method method, Object[] args) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalStaticMethodSig(method);
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsStaticMethod(method, args)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

    @Override public final boolean permitsFieldGet(Field field, Object receiver) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalFieldSig(field);  // Only non-cacheable Whitelists care about get vs. set
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsFieldGet(field, receiver)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

    @Override public final boolean permitsFieldSet(Field field, Object receiver, Object value) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalFieldSig(field);  // Only non-cacheable Whitelists care about get vs. set
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsFieldSet(field, receiver, value)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldGet(Field field) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalStaticFieldSig(field);  // Only non-cacheable Whitelists care about get vs. set
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsStaticFieldGet(field)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldSet(Field field, Object value) {
        synchronized (this.delegates) {
            String sigString = Whitelist.canonicalStaticFieldSig(field);  // Only non-cacheable Whitelists care about get vs. set
            Boolean b = permittedCache.get(sigString);

            if (b == Boolean.TRUE) {
                return true;
            }

            for (Whitelist delegate : sortedDelegates) {
                if (b == Boolean.FALSE && delegate instanceof CacheableWhitelist) {
                    // Skip CacheableWhitelists if we already know none of them permit the method
                    continue;
                }
                if (delegate.permitsStaticFieldSet(field, value)) {
                    permittedCache.put(sigString, delegate instanceof CacheableWhitelist); // If we get a hit from non-Cacheable whitelists, none of the CacheableWhitelists permitted it
                    return true;
                }
            }
            permittedCache.put(sigString, Boolean.FALSE);
        }
        return false;
    }

}
