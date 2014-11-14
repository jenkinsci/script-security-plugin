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

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.google.common.primitives.Primitives;
import groovy.lang.GString;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import org.apache.commons.lang.ClassUtils;

/**
 * Assists in determination of which method or other JVM element is actually about to be called by Groovy.
 * Most of this just duplicates what {@link java.lang.invoke.MethodHandles.Lookup} and {@link java.lang.invoke.MethodHandle#asType} do,
 * but {@link org.codehaus.groovy.vmplugin.v7.TypeTransformers} (Groovy 2) shows that there are Groovy-specific complications.
 * Comments in https://github.com/kohsuke/groovy-sandbox/issues/7 note that it would be great for the sandbox itself to just tell us what the call site is so we would not have to guess.
 */
class GroovyCallSiteSelector {

    private static boolean matches(@Nonnull Class<?>[] parameterTypes, @Nonnull Object[] parameters) {
        if (parameters.length != parameterTypes.length) {
            return false;
        }
        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameters[i] == null) {
                if (parameterTypes[i].isPrimitive()) {
                    return false;
                } else {
                    // A null argument is assignable to any reference-typed parameter.
                    continue;
                }
            }
            if (parameterTypes[i].isInstance(parameters[i])) {
                // OK, this parameter matches.
                continue;
            }
            if (
                    parameterTypes[i].isPrimitive()
                    && parameters[i] != null
                    && ClassUtils.primitiveToWrapper(parameterTypes[i]).isInstance(parameters[i])
            ) {
                // Groovy passes primitive values as objects (for example, passes 0 as Integer(0))
                // The prior test fails as int.class.isInstance(new Integer(0)) returns false.
                continue;
            }
            // TODO what about a primitive parameter type and a wrapped parameter?
            if (parameterTypes[i] == String.class && parameters[i] instanceof GString) {
                // Cf. SandboxInterceptorTest and class Javadoc.
                continue;
            }
            // Mismatch.
            return false;
        }
        return true;
    }

    /**
     * Looks up the most general possible definition of a given method call.
     * Preferentially searches for compatible definitions in supertypes.
     * @param receiver an actual receiver object
     * @param method the method name
     * @param args a set of actual arguments
     */
    public static @CheckForNull Method method(@Nonnull Object receiver, @Nonnull String method, @Nonnull Object[] args) {
        for (Class<?> c : types(receiver)) {
            Method candidate = null;
            for (Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(method) && matches(m.getParameterTypes(), args)) {
                    if (candidate == null || isMoreSpecific(m, candidate)) {
                        candidate = m;
                    }
                }
            }
            if (candidate != null) {
                return candidate;
            }
        }
        return null;
    }

    public static @CheckForNull Constructor<?> constructor(@Nonnull Class<?> receiver, @Nonnull Object[] args) {
        for (Constructor<?> c : receiver.getDeclaredConstructors()) {
            if (matches(c.getParameterTypes(), args)) {
                return c;
            }
        }
        return null;
    }

    public static @CheckForNull Method staticMethod(@Nonnull Class<?> receiver, @Nonnull String method, @Nonnull Object[] args) {
        // TODO should we check for inherited static calls?
        Method candidate = null;
        for (Method m : receiver.getDeclaredMethods()) {
            if (m.getName().equals(method) && matches(m.getParameterTypes(), args)) {
                if (candidate == null || isMoreSpecific(m, candidate)) {
                    candidate = m;
                }
            }
        }
        return candidate;
    }

    public static @CheckForNull Field field(@Nonnull Object receiver, @Nonnull String field) {
        for (Class<?> c : types(receiver)) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getName().equals(field)) {
                    return f;
                }
            }
        }
        return null;
    }

    public static @CheckForNull Field staticField(@Nonnull Class<?> receiver, @Nonnull String field) {
        for (Field f : receiver.getDeclaredFields()) {
            if (f.getName().equals(field)) {
                return f;
            }
        }
        return null;
    }

    private static Iterable<Class<?>> types(@Nonnull Object o) {
        Set<Class<?>> types = new LinkedHashSet<Class<?>>();
        visitTypes(types, o.getClass());
        return types;
    }
    private static void visitTypes(@Nonnull Set<Class<?>> types, @Nonnull Class<?> c) {
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

    private static boolean isMoreSpecific(Method more, Method less) {
        Class<?>[] moreParams = more.getParameterTypes();
        Class<?>[] lessParams = less.getParameterTypes();
        assert moreParams.length == lessParams.length;
        for (int i = 0; i < moreParams.length; i++) {
            Class<?> moreParam = Primitives.wrap(moreParams[i]);
            Class<?> lessParam = Primitives.wrap(lessParams[i]);
            if (moreParam.isAssignableFrom(lessParam)) {
                return false;
            } else if (lessParam.isAssignableFrom(moreParam)) {
                return true;
            }
        }
        // Incomparable. Arbitrarily pick one of them.
        return more.toString().compareTo(less.toString()) > 0;
    }

    private GroovyCallSiteSelector() {}

}
