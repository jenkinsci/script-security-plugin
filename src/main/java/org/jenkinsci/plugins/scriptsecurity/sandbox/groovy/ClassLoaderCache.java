/*
 * The MIT License
 *
 * Copyright 2019 CloudBees, Inc.
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

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;

/**
 * A cache keyed by {@link ClassLoader} in which values may safely refer to keys (including their loaded classes) without introducing memory leaks.
 * @see <a href="https://bugs.openjdk.java.net/browse/JDK-6389107">JDK-6389107</a>
 */
@SuppressWarnings("unchecked")
final class ClassLoaderCache<V> {

    private static final Object HACK_KEY = ClassLoaderCache.class.getName() + "$$__$$"; // not a valid package name

    /**
     * Need a {@link Map}-valued instance field in {@link ClassLoader} which is never null and whose entries are never enumerated.
     * We will stash a mistyped value in there under a special {@link #HACK_KEY}.
     * This is nothing more than a way to get a {@link ClassLoader} to strongly refer to a value of our choice.
     */
    private static @CheckForNull Map<Object, Object> hack(ClassLoader loader) {
        try {
            Field f = ClassLoader.class.getDeclaredField("package2certs");
            f.setAccessible(true);
            return (Map) f.get(loader);
        } catch (Exception x) {
            // TODO https://github.com/eclipse/openj9/blob/master/jcl/src/java.base/share/classes/java/lang/ClassLoader.java has rather different fields from OpenJDK’s
            Logger.getLogger(ClassLoaderCache.class.getName()).log(Level.WARNING, "unsupported JRE, maybe J9?", x);
            return null;
        }
    }

    private final Function<ClassLoader, V> func;

    ClassLoaderCache(Function<ClassLoader, V> func) {
        this.func = func;
    }

    V get(ClassLoader key) {
        Map<Object, Object> hack = hack(key);
        if (hack == null) {
            // disable cache in this case; or could fall back to a WeakHashMap<ClassLoader, SoftReference<V>>
            return func.apply(key);
        }
        Map<ClassLoaderCache<?>, Object> caches;
        synchronized (hack) {
            caches = (Map<ClassLoaderCache<?>, Object>) hack.computeIfAbsent(HACK_KEY, hackKey -> new WeakHashMap<ClassLoaderCache<?>, Object>());
        }
        synchronized (caches) {
            return (V) caches.computeIfAbsent(this, _this -> func.apply(key));
        }
    }

    /**
     * A cache keyed by {@link Class} in which values may safely refer to keys (including their defining loaders) without introducing memory leaks.
     */
    static final class ClassCache<V> {

        private final Function<Class<?>, V> func;
        private final ClassLoaderCache<Map<Class<?>, V>> delegate;

        ClassCache(Function<Class<?>, V> func) {
            this.func = func;
            delegate = new ClassLoaderCache<>(loader -> new ConcurrentHashMap<>());
        }

        V get(Class<?> key) {
            return delegate.get(key.getClassLoader()).computeIfAbsent(key, func);
        }

    }

}
