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

import net.jcip.annotations.GuardedBy;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Aggregates several whitelists.
 */
public class ProxyWhitelist extends Whitelist {
    @GuardedBy("lock")
    private Collection<? extends Whitelist> originalDelegates;

    @GuardedBy("lock")
    final List<Whitelist> delegates = new ArrayList<Whitelist>();

    @GuardedBy("lock")
    private final List<EnumeratingWhitelist.MethodSignature> methodSignatures = new ArrayList<EnumeratingWhitelist.MethodSignature>();

    @GuardedBy("lock")
    private final List<EnumeratingWhitelist.NewSignature> newSignatures = new ArrayList<EnumeratingWhitelist.NewSignature>();

    @GuardedBy("lock")
    private final List<EnumeratingWhitelist.MethodSignature> staticMethodSignatures = new ArrayList<EnumeratingWhitelist.MethodSignature>();

    @GuardedBy("lock")
    private final List<EnumeratingWhitelist.FieldSignature> fieldSignatures = new ArrayList<EnumeratingWhitelist.FieldSignature>();

    @GuardedBy("lock")
    private final List<EnumeratingWhitelist.FieldSignature> staticFieldSignatures = new ArrayList<EnumeratingWhitelist.FieldSignature>();

    /** anything wrapping us, so that we can propagate {@link #reset} calls up the chain */
    @GuardedBy("lock")
    private final Map<ProxyWhitelist,Void> wrappers = new WeakHashMap<ProxyWhitelist,Void>();

    // TODO Consider StampedLock when we switch to Java8 for better performance - https://dzone.com/articles/a-look-at-stampedlock
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public ProxyWhitelist(Collection<? extends Whitelist> delegates) {
        reset(delegates);
    }

    /**
     * This should only be called from {@link ProxyWhitelist#reset(Collection)}. So we can assume that a write 
     * lock is held.
     * @param wrapper the wrapper
     */
    private void addWrapper(ProxyWhitelist wrapper) {
        assert wrapper.lock.writeLock().isHeldByCurrentThread();
        lock.writeLock().lock();
        try {
            wrappers.put(wrapper, null);
            lock.readLock().lock();
        } finally {
            lock.writeLock().unlock();
        }
        try {
            for (Whitelist subdelegate : delegates) {
                if (subdelegate instanceof EnumeratingWhitelist) {
                    ((EnumeratingWhitelist) subdelegate).clearCache();  // We only care about top-level cache
                    continue; // this is handled specially
                }
                wrapper.delegates.add(subdelegate);
            }
            wrapper.methodSignatures.addAll(methodSignatures);
            wrapper.newSignatures.addAll(newSignatures);
            wrapper.staticMethodSignatures.addAll(staticMethodSignatures);
            wrapper.fieldSignatures.addAll(fieldSignatures);
            wrapper.staticFieldSignatures.addAll(staticFieldSignatures);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * This only exists for consistency. Access to originalDelegates should require a read lock and this 
     * method should be called by a <b>wrapped</b> instance's {@link ProxyWhitelist#reset(Collection)}.
     */
    private void reset() {
        lock.writeLock().lock();
        try {
            reset(originalDelegates);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public final void reset(Collection<? extends Whitelist> delegates) {
        ReentrantReadWriteLock.WriteLock writer = lock.writeLock();
        writer.lock();

        try {
            originalDelegates = delegates;
            this.delegates.clear();
            methodSignatures.clear();
            newSignatures.clear();
            staticMethodSignatures.clear();
            fieldSignatures.clear();
            staticFieldSignatures.clear();

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
                    ew.clearCache();
                } else if (delegate instanceof ProxyWhitelist) {
                    ProxyWhitelist pw = (ProxyWhitelist) delegate;
                    pw.addWrapper(this);
                } else {
                    Objects.requireNonNull(delegate);
                    this.delegates.add(delegate);
                }
            }
            for (ProxyWhitelist pw : wrappers.keySet()) {
                pw.reset();
            }
            if (this.wrappers.isEmpty()) {  // Top-level ProxyWhitelist should be the only cache
                // Top-level ProxyWhitelist should precache the statically permitted signatures
                ((EnumeratingWhitelist)(this.delegates.get(0))).precache();
            }
        } finally {
            writer.unlock();
        }
    }

    public ProxyWhitelist(Whitelist... delegates) {
        this(Arrays.asList(delegates));
    }

    @Override public final boolean permitsMethod(Method method, Object receiver, Object[] args) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsMethod(method, receiver, args)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        return false;
    }

    @Override public final boolean permitsConstructor(Constructor<?> constructor, Object[] args) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsConstructor(constructor, args)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        return false;
    }

    @Override public final boolean permitsStaticMethod(Method method, Object[] args) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsStaticMethod(method, args)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        return false;
    }

    @Override public final boolean permitsFieldGet(Field field, Object receiver) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsFieldGet(field, receiver)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        return false;
    }

    @Override public final boolean permitsFieldSet(Field field, Object receiver, Object value) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsFieldSet(field, receiver, value)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }

        return false;
    }

    @Override public final boolean permitsStaticFieldGet(Field field) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsStaticFieldGet(field)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldSet(Field field, Object value) {
        lock.readLock().lock();
        try {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsStaticFieldSet(field, value)) {
                    return true;
                }
            }
        } finally {
            lock.readLock().unlock();
        }
        return false;
    }

    @Override public String toString() {
        lock.readLock().lock();
        try {
            return super.toString() + delegates;
        } finally {
            lock.readLock().unlock();
        }
    }

}
