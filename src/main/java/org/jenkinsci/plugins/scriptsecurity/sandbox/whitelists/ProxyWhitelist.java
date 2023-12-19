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

import edu.umd.cs.findbugs.annotations.NonNull;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

/**
 * Aggregates several whitelists.
 */
public class ProxyWhitelist extends Whitelist {

    private volatile Whitelist[] delegates;

    public ProxyWhitelist(Collection<? extends Whitelist> delegates) {
        reset(delegates);
    }

    public final void reset(Collection<? extends Whitelist> delegates) {
        this.delegates = delegates.toArray(Whitelist[]::new);
    }

    public ProxyWhitelist(Whitelist... delegates) {
        this(Arrays.asList(delegates));
    }

    /**
     * Called before {@link #permitsMethod} and similar methods.
     * May call {@link #reset(Collection)}.
     */
    protected void beforePermits() {}

    private void callBeforePermits() {
        beforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate instanceof ProxyWhitelist) {
                ((ProxyWhitelist) delegate).callBeforePermits();
            }
        }
    }

    @Override public final boolean permitsMethod(@NonNull Method method, @NonNull Object receiver, @NonNull Object[] args) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsMethod(method, receiver, args)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsConstructor(@NonNull Constructor<?> constructor, @NonNull Object[] args) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsConstructor(constructor, args)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticMethod(@NonNull Method method, @NonNull Object[] args) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsStaticMethod(method, args)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldGet(@NonNull Field field, @NonNull Object receiver) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsFieldGet(field, receiver)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsFieldSet(@NonNull Field field, @NonNull Object receiver, Object value) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsFieldSet(field, receiver, value)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldGet(@NonNull Field field) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsStaticFieldGet(field)) {
                return true;
            }
        }
        return false;
    }

    @Override public final boolean permitsStaticFieldSet(@NonNull Field field, Object value) {
        callBeforePermits();
        for (Whitelist delegate : delegates) {
            if (delegate.permitsStaticFieldSet(field, value)) {
                return true;
            }
        }
        return false;
    }

    @Override public String toString() {
        return super.toString() + Arrays.toString(delegates);
    }

}
