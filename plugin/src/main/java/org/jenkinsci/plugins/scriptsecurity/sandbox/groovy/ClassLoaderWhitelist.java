package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * {@link Whitelist} that allows everything defined from a specific classloader.
 *
 * @author Jesse Glick
 */
public final class ClassLoaderWhitelist extends Whitelist {
    private final ClassLoader scriptLoader;

    public ClassLoaderWhitelist(ClassLoader scriptLoader) {
        this.scriptLoader = scriptLoader;
    }

    private boolean permits(Class<?> declaringClass) {
        return declaringClass.getClassLoader() == scriptLoader;
    }

    @Override public boolean permitsMethod(@NonNull Method method, @NonNull Object receiver, @NonNull Object[] args) {
        return permits(method.getDeclaringClass()) && !isIllegalSyntheticMethod(method);
    }

    @Override public boolean permitsConstructor(@NonNull Constructor<?> constructor, @NonNull Object[] args) {
        return permits(constructor.getDeclaringClass()) && !isIllegalSyntheticConstructor(constructor);
    }

    @Override public boolean permitsStaticMethod(@NonNull Method method, @NonNull Object[] args) {
        return permits(method.getDeclaringClass()) && !isIllegalSyntheticMethod(method);
    }

    @Override public boolean permitsFieldGet(@NonNull Field field, @NonNull Object receiver) {
        return permits(field.getDeclaringClass()) && !isIllegalSyntheticField(field);
    }

    @Override public boolean permitsFieldSet(@NonNull Field field, @NonNull Object receiver, Object value) {
        return permits(field.getDeclaringClass()) && !isIllegalSyntheticField(field);
    }

    @Override public boolean permitsStaticFieldGet(@NonNull Field field) {
        return permits(field.getDeclaringClass()) && !isIllegalSyntheticField(field);
    }

    @Override public boolean permitsStaticFieldSet(@NonNull Field field, Object value) {
        return permits(field.getDeclaringClass()) && !isIllegalSyntheticField(field);
    }

    /**
     * Checks whether a given field was synthetically created by the Groovy compiler and should be inaccessible even if
     * it is declared by a class defined by the specified class loader.
     */
    private static boolean isIllegalSyntheticField(Field field) {
        if (!field.isSynthetic()) {
            return false;
        }
        Class<?> declaringClass = field.getDeclaringClass();
        Class<?> enclosingClass = declaringClass.getEnclosingClass();
        if (field.getType() == enclosingClass && field.getName().startsWith("this$")) {
            // Synthetic field added to inner classes to reference the outer class.
            return false;
        } else if (declaringClass.isEnum() && Modifier.isStatic(field.getModifiers()) && field.getName().equals("$VALUES")) {
            // Synthetic field added by Groovy to enum classes to hold the enum constants.
            return false;
        }
        return true;
    }

    /**
     * Checks whether a given method was synthetically created by the Groovy compiler and should be inaccessible even
     * if it is declared by a class defined by the specified class loader.
     */
    private static boolean isIllegalSyntheticMethod(Method method) {
        if (!method.isSynthetic()) {
            return false;
        } else if (Modifier.isStatic(method.getModifiers()) && method.getDeclaringClass().isEnum() && method.getName().equals("$INIT")) {
            // Synthetic method added by Groovy to enum classes used to initialize the enum constants.
            return false;
        }
        return true;
    }

    /**
     * Checks whether a given constructor was created by the Groovy compiler (or groovy-sandbox) and
     * should be inaccessible even if it is declared by a class defined by the specified class loader.
     */
    private static boolean isIllegalSyntheticConstructor(Constructor constructor) {
        if (!constructor.isSynthetic()) {
            return false;
        }
        Class<?> declaringClass = constructor.getDeclaringClass();
        Class<?> enclosingClass = declaringClass.getEnclosingClass();
        if (enclosingClass != null && constructor.getParameters().length > 0 && constructor.getParameterTypes()[0] == enclosingClass) {
            // Synthetic constructor added by Groovy to anonymous classes.
            return false;
        }
        return true;
    }
}
