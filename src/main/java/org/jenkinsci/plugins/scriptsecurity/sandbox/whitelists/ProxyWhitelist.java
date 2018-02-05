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

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Aggregates several whitelists.
 
 */
public class ProxyWhitelist extends Whitelist {
    
    private Collection<? extends Whitelist> originalDelegates;
    private final List<Whitelist> delegates = new ArrayList<Whitelist>();

    private StaticWhitelist aggregated;

    /** anything wrapping us, so that we can propagate {@link #reset} calls up the chain */
    private final Map<ProxyWhitelist,Void> wrappers = new WeakHashMap<ProxyWhitelist,Void>();

    public ProxyWhitelist(Collection<? extends Whitelist> delegates) {
        reset(delegates);
    }

    private void reset() {
        reset(originalDelegates);
    }

    public final void reset(Collection<? extends Whitelist> delegates) {
        synchronized (this.delegates) {
            originalDelegates = delegates;
            this.delegates.clear();

            List<EnumeratingWhitelist> listsToAggregate = new ArrayList<EnumeratingWhitelist>();

            for (Whitelist delegate : delegates) {
                if (delegate instanceof EnumeratingWhitelist) {
                    listsToAggregate.add((EnumeratingWhitelist)delegate);
                } else if (delegate instanceof ProxyWhitelist) {
                    ProxyWhitelist pw = (ProxyWhitelist) delegate;
                    pw.wrappers.put(this, null);
                    for (Whitelist subdelegate : pw.delegates) {
                        if (subdelegate instanceof EnumeratingWhitelist) {
                            continue; // this is handled specially
                        }
                        this.delegates.add(subdelegate);
                    }
                    listsToAggregate.add(pw.aggregated);
                } else {
                    this.delegates.add(delegate);
                }
            }

            // Roll up the aggregated lists
            this.aggregated = new StaticWhitelist(listsToAggregate.toArray(new EnumeratingWhitelist[listsToAggregate.size()]));
            this.delegates.add(0, aggregated);

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
            for (Whitelist delegate : delegates) {
                if (delegate.permitsMethod(method, receiver, args)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override public final boolean permitsConstructor(Constructor<?> constructor, Object[] args) {
        synchronized (this.delegates) {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsConstructor(constructor, args)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticMethod(Method method, Object[] args) {
        synchronized (this.delegates) {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsStaticMethod(method, args)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldGet(Field field, Object receiver) {
        synchronized (this.delegates) {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsFieldGet(field, receiver)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldSet(Field field, Object receiver, Object value) {
        synchronized (this.delegates) {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsFieldSet(field, receiver, value)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldGet(Field field) {
        synchronized (this.delegates) {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsStaticFieldGet(field)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldSet(Field field, Object value) {
        synchronized (this.delegates) {
            for (Whitelist delegate : delegates) {
                if (delegate.permitsStaticFieldSet(field, value)) {
                    return true;
                }
            }
        }
        return false;
    }

}
