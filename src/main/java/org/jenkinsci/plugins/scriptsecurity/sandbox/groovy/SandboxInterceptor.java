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

import groovy.lang.Closure;
import groovy.lang.GroovyRuntimeException;
import groovy.lang.MetaMethod;
import groovy.lang.MissingMethodException;
import groovy.lang.MissingPropertyException;
import groovy.lang.Script;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.lang.reflect.Modifier;
import org.codehaus.groovy.runtime.DateGroovyMethods;
import org.codehaus.groovy.runtime.DefaultGroovyMethods;
import org.codehaus.groovy.runtime.EncodingGroovyMethods;
import org.codehaus.groovy.runtime.InvokerHelper;
import org.codehaus.groovy.runtime.MetaClassHelper;
import org.codehaus.groovy.runtime.NullObject;
import org.codehaus.groovy.runtime.ProcessGroovyMethods;
import org.codehaus.groovy.runtime.SqlGroovyMethods;
import org.codehaus.groovy.runtime.StringGroovyMethods;
import org.codehaus.groovy.runtime.SwingGroovyMethods;
import org.codehaus.groovy.runtime.XmlGroovyMethods;
import org.codehaus.groovy.runtime.metaclass.ClosureMetaMethod;
import org.codehaus.groovy.runtime.typehandling.NumberMathModificationInfo;
import org.codehaus.groovy.syntax.Types;
import org.codehaus.groovy.tools.DgmConverter;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.kohsuke.groovy.sandbox.GroovyInterceptor;
import org.kohsuke.groovy.sandbox.impl.Checker;

@SuppressWarnings("rawtypes")
final class SandboxInterceptor extends GroovyInterceptor {

    private static final Logger LOGGER = Logger.getLogger(SandboxInterceptor.class.getName());

    private final Whitelist whitelist;
    
    SandboxInterceptor(Whitelist whitelist) {
        this.whitelist = whitelist;
    }

    /** should be synchronized with {@link DgmConverter} */
    private static final Class<?>[] DGM_CLASSES = {
        DefaultGroovyMethods.class,
        StringGroovyMethods.class,
        SwingGroovyMethods.class,
        SqlGroovyMethods.class,
        XmlGroovyMethods.class,
        EncodingGroovyMethods.class,
        DateGroovyMethods.class,
        ProcessGroovyMethods.class,
    };

    /**
     * Mirrors {@link NumberMathModificationInfo}.NAMES: arithmetic operators on Number types dispatched
     * through Groovy's compiled-in bytecode, not as Java-declared methods, so they appear as null from
     * {@link GroovyCallSiteSelector#method}, requiring the fast-path below.
     */
    private static final Set<String> NUMBER_MATH_NAMES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("plus", "minus", "multiply", "div", "compareTo", "or", "and", "xor", "intdiv", "mod", "leftShift", "rightShift", "rightShiftUnsigned")));

    @Override public Object onMethodCall(GroovyInterceptor.Invoker invoker, Object receiver, String method, Object... args) throws Throwable {
        Method m = GroovyCallSiteSelector.method(receiver, method, args);
        if (m == null) {
            if (receiver instanceof Number && NUMBER_MATH_NAMES.contains(method)) {
                // A ClosureMetaMethod override would reach super without a whitelist check.
                for (MetaMethod mm : DefaultGroovyMethods.getMetaClass(receiver).respondsTo(receiver, method)) {
                    if (mm instanceof ClosureMetaMethod) {
                        throw new MissingMethodException(method, receiver.getClass(), args);
                    }
                }
                // Synthetic methods like Integer.plus(Integer) not found by Java reflection.
                return super.onMethodCall(invoker, receiver, method, args);
            }

            // look for GDK methods
            Object[] selfArgs = new Object[args.length + 1];
            selfArgs[0] = receiver;
            System.arraycopy(args, 0, selfArgs, 1, args.length);
            Method foundDgmMethod = null;

            for (Class<?> dgmClass : DGM_CLASSES) {
                Method dgmMethod = GroovyCallSiteSelector.staticMethod(dgmClass, method, selfArgs);
                if (dgmMethod != null) {
                    if (whitelist.permitsStaticMethod(dgmMethod, selfArgs)) {
                        return super.onMethodCall(invoker, receiver, method, args);
                    } else if (foundDgmMethod == null) {
                        foundDgmMethod = dgmMethod;
                    }
                }
            }

            for (SandboxMethodContributor contributor : SandboxMethodContributor.all()) {
                for (Class<?> dgmClass : contributor.getContributedClasses()) {
                    Method dgmMethod = GroovyCallSiteSelector.staticMethod(dgmClass, method, selfArgs);
                    if (dgmMethod != null) {
                        if (whitelist.permitsStaticMethod(dgmMethod, selfArgs)) {
                            try {
                                return dgmMethod.invoke(null, selfArgs);
                            } catch (InvocationTargetException e) {
                                throw e.getCause();
                            }
                        } else if (foundDgmMethod == null) {
                            foundDgmMethod = dgmMethod;
                        }
                    }
                }
            }

            // Some methods are found by GroovyCallSiteSelector in both DefaultGroovyMethods and StringGroovyMethods, so
            // we're iterating over the whole list before we decide to fail out on the first failure we found.
            if (foundDgmMethod != null) {
                throw StaticWhitelist.rejectStaticMethod(foundDgmMethod);
            }

            // allow calling Closure elements of Maps as methods
            if (receiver instanceof Map) {
                Object element = onMethodCall(invoker, receiver, "get", method);
                if (element instanceof Closure) {
                    return onMethodCall(invoker, element, "call", args);
                }
            }

            // Allow calling closure variables from a script binding as methods
            if (receiver instanceof Script) {
                Script s = (Script) receiver;
                if (s.getBinding().hasVariable(method)) {
                    Object var = s.getBinding().getVariable(method);
                    if (!InvokerHelper.getMetaClass(var).respondsTo(var, "call", args).isEmpty()) {
                        return onMethodCall(invoker, var, "call", args);
                    }
                }
            }

            // SECURITY-3931: null receivers are substituted with NullObject in Checker.checkedCall.
            // If no method was found on NullObject, throw NPE as Groovy normally would rather than
            // routing through invokeMethod, which would trigger whitelist rejection or category dispatch.
            if (receiver instanceof NullObject) {
                throw new NullPointerException("Cannot invoke method " + method + "() on null object");
            }

            // if no matching method, look for catchAll "invokeMethod"
            try {
                receiverClass(receiver).getMethod("invokeMethod", String.class, Object.class);
                return onMethodCall(invoker, receiver, "invokeMethod", method, args);
            } catch (NoSuchMethodException e) {
                // fall through
            }

            // no such method exists
            throw new MissingMethodException(method, receiverClass(receiver), args);
        } else if (StaticWhitelist.isPermanentlyBlacklistedMethod(m)) {
            throw StaticWhitelist.rejectMethod(m);
        } else if (permitsMethod(whitelist, m, receiver, args)) {
            return super.onMethodCall(invoker, receiver, method, args);
        } else if (method.equals("invokeMethod") && args.length == 2 && args[0] instanceof String && args[1] instanceof Object[]) {
            throw StaticWhitelist.rejectMethod(m, EnumeratingWhitelist.getName(receiverClass(receiver)) + " " + args[0] + printArgumentTypes((Object[]) args[1]));
        } else {
            throw rejectMethod(m);
        }
    }

    // SECURITY-3931: groovy-sandbox now routes null receivers through the interceptor chain.
    // Use NullObject.class wherever receiver.getClass() was called, to avoid NPE.
    private static Class<?> receiverClass(Object receiver) {
        return receiver == null ? NullObject.class : receiver.getClass();
    }

    @Override public Object onNewInstance(GroovyInterceptor.Invoker invoker, Class receiver, Object... args) throws Throwable {
        Constructor<?> c = GroovyCallSiteSelector.constructor(receiver, args);
        if (c == null) {
            throw new RejectedAccessException("No such constructor found: new " + EnumeratingWhitelist.getName(receiver) + printArgumentTypes(args));
        } else if (StaticWhitelist.isPermanentlyBlacklistedConstructor(c)) {
            throw StaticWhitelist.rejectNew(c);
        } else if (whitelist.permitsConstructor(c, args)) {
            if (c.getParameterCount() == 0 && args.length == 1 && args[0] instanceof Map) {
                // c.f. https://github.com/apache/groovy/blob/41b990d0a20e442f29247f0e04cbed900f3dcad4/src/main/groovy/lang/MetaClassImpl.java#L1728-L1738
                // We replace the arguments that the invoker will use to construct the object with the empty array to
                // bypass Groovy's default handling for implicit map constructors.
                Object newInstance = super.onNewInstance(invoker, receiver, new Object[0]);
                if (newInstance == null) {
                    // We were called by Checker.preCheckedCast. Our options here are limited, so we just reject everything.
                    throw new UnsupportedOperationException("Groovy map constructors may only be invoked using the 'new' keyword in the sandbox (attempted to construct " + receiver + " via a Groovy cast)");
                }
                // The call to Map.entrySet below may be on a user-defined type, which could be a problem if we iterated
                // over it here to pre-check the property assignments and then let Groovy iterate over it again to
                // actually perform them, so we only iterate over it once and perform the property assignments
                // ourselves using sandbox-aware methods.
                for (Map.Entry<Object, Object> entry : ((Map<Object, Object>) args[0]).entrySet()) {
                    Checker.checkedSetProperty(newInstance, entry.getKey(), false, false, Types.ASSIGN, entry.getValue());
                }
                return newInstance;
            }
            return super.onNewInstance(invoker, receiver, args);
        } else {
            throw StaticWhitelist.rejectNew(c);
        }
    }

    @Override public Object onStaticCall(GroovyInterceptor.Invoker invoker, Class receiver, String method, Object... args) throws Throwable {
        Method m = GroovyCallSiteSelector.staticMethod(receiver, method, args);
        if (m == null) {
            // TODO consider DefaultGroovyStaticMethods
            throw new RejectedAccessException("No such static method found: staticMethod " + EnumeratingWhitelist.getName(receiver) + " " + method + printArgumentTypes(args));
        } else if (StaticWhitelist.isPermanentlyBlacklistedStaticMethod(m)) {
            throw StaticWhitelist.rejectStaticMethod(m);
        } else if (whitelist.permitsStaticMethod(m, args)) {
            return super.onStaticCall(invoker, receiver, method, args);
        } else {
            throw StaticWhitelist.rejectStaticMethod(m);
        }
    }

    @Override public Object onSetProperty(GroovyInterceptor.Invoker invoker, final Object receiver, final String property, Object value) throws Throwable {
        if (receiver instanceof Script && !property.equals("binding") && !property.equals("metaClass")) {
            return super.onSetProperty(invoker, receiver, property, value);
        }
        if (receiver == null) {
            throw new NullPointerException("Cannot set property '" + property + "' on null object");
        }
        Rejector rejector = null; // avoid creating exception objects unless and until thrown
        // https://github.com/kohsuke/groovy-sandbox/issues/7 need to explicitly check for getters and setters:
        Object[] valueArg = new Object[] {value};
        String setter = "set" + MetaClassHelper.capitalize(property);
        List<Method> setterMethods = GroovyCallSiteSelector.methods(receiver, setter, m -> m.getParameterCount() == 1);
        final Method setterMethod = setterMethods.size() == 1
                ? setterMethods.get(0) // If there is only a single setter, the argument will be cast to match the declared parameter type.
                : GroovyCallSiteSelector.method(receiver, setter, valueArg); // If there are multiple setters, MultipleSetterProperty just calls invokeMethod.
        if (setterMethod != null) {
            if (permitsMethod(whitelist, setterMethod, receiver, valueArg)) {
                preCheckArgumentCasts(setterMethod, valueArg);
                return super.onSetProperty(invoker, receiver, property, valueArg[0]);
            } else if (rejector == null) {
                rejector = () -> rejectMethod(setterMethod);
            }
        }
        Object[] propertyValueArgs = new Object[] {property, value};
        final Method setPropertyMethod = GroovyCallSiteSelector.method(receiver, "setProperty", propertyValueArgs);
        if (setPropertyMethod != null && !isSyntheticMethod(receiver, setPropertyMethod)) {
            if (whitelist.permitsMethod(setPropertyMethod, receiver, propertyValueArgs)) {
                preCheckArgumentCasts(setPropertyMethod, propertyValueArgs);
                return super.onSetProperty(invoker, receiver, property, propertyValueArgs[1]);
            } else if (rejector == null) {
                rejector = () -> StaticWhitelist.rejectMethod(setPropertyMethod, receiverClass(receiver).getName() + "." + property);
            }
        }
        final Field field = GroovyCallSiteSelector.field(receiver, property);
        if (field != null) {
            if (permitsFieldSet(whitelist, field, receiver, value)) {
                Object snapshotValue = Checker.preCheckedCast(field.getType(), value, false, false, false).call();
                return super.onSetProperty(invoker, receiver, property, snapshotValue);
            } else if (rejector == null) {
                rejector = () -> rejectField(field);
            }
        }
        if (receiver instanceof Class) {
            List<Method> staticSetterMethods = GroovyCallSiteSelector.staticMethods((Class) receiver, setter, m -> m.getParameterCount() == 1);
            final Method staticSetterMethod = staticSetterMethods.size() == 1
                ? staticSetterMethods.get(0) // If there is only a single setter, the value will be cast to match the declared parameter type.
                : GroovyCallSiteSelector.staticMethod((Class) receiver, setter, valueArg); // If there are multiple setters, MultipleSetterProperty just calls invokeMethod.
            if (staticSetterMethod != null) {
                if (whitelist.permitsStaticMethod(staticSetterMethod, valueArg)) {
                    preCheckArgumentCasts(staticSetterMethod, valueArg);
                    return super.onSetProperty(invoker, receiver, property, valueArg[0]);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticMethod(staticSetterMethod);
                }
            }
            final Field staticField = GroovyCallSiteSelector.staticField((Class) receiver, property);
            if (staticField != null) {
                if (whitelist.permitsStaticFieldSet(staticField, value)) {
                    Object snapshotValue = Checker.preCheckedCast(staticField.getType(), value, false, false, false).call();
                    return super.onSetProperty(invoker, receiver, property, snapshotValue);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticField(staticField);
                }
            }
        }
        throw rejector != null ? rejector.reject() : unclassifiedField(receiver, property);
    }

    @Override public Object onGetProperty(GroovyInterceptor.Invoker invoker, final Object receiver, final String property) throws Throwable {
        MissingPropertyException mpe = null;
        if (receiver instanceof Script) { // SimpleTemplateEngine "out" variable, and anything else added in a binding
            try {
                ((Script) receiver).getBinding().getVariable(property); // do not let it go to Script.super.getProperty
                return super.onGetProperty(invoker, receiver, property);
            } catch (MissingPropertyException x) {
                mpe = x; // throw only if we are not whitelisted
            }
        }
        if (receiver == null) {
            throw new NullPointerException("Cannot get property '" + property + "' on null object");
        }
        if (property.equals("length") && receiverClass(receiver).isArray()) {
            return super.onGetProperty(invoker, receiver, property);
        }
        Rejector rejector = null;
        Object[] noArgs = new Object[] {};
        String getter = "get" + MetaClassHelper.capitalize(property);
        final Method getterMethod = GroovyCallSiteSelector.method(receiver, getter, noArgs);
        if (getterMethod != null) {
            if (permitsMethod(whitelist, getterMethod, receiver, noArgs)) {
                return super.onGetProperty(invoker, receiver, property);
            } else if (rejector == null) {
                rejector = () -> rejectMethod(getterMethod);
            }
        }
        String booleanGetter = "is" + MetaClassHelper.capitalize(property);
        final Method booleanGetterMethod = GroovyCallSiteSelector.method(receiver, booleanGetter, noArgs);
        if (booleanGetterMethod != null && booleanGetterMethod.getReturnType() == boolean.class) {
            if (permitsMethod(whitelist, booleanGetterMethod, receiver, noArgs)) {
                return super.onGetProperty(invoker, receiver, property);
            } else if (rejector == null) {
                rejector = () -> rejectMethod(booleanGetterMethod);
            }
        }
        // look for GDK methods
        Object[] selfArgs = new Object[] {receiver};
        for (Class<?> dgmClass : DGM_CLASSES) {
            final Method dgmGetterMethod = GroovyCallSiteSelector.staticMethod(dgmClass, getter, selfArgs);
            if (dgmGetterMethod != null) {
                if (whitelist.permitsStaticMethod(dgmGetterMethod, selfArgs)) {
                    return super.onGetProperty(invoker, receiver, property);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticMethod(dgmGetterMethod);
                }
            }
            final Method dgmBooleanGetterMethod = GroovyCallSiteSelector.staticMethod(dgmClass, booleanGetter, selfArgs);
            if (dgmBooleanGetterMethod != null && dgmBooleanGetterMethod.getReturnType() == boolean.class) {
                if (whitelist.permitsStaticMethod(dgmBooleanGetterMethod, selfArgs)) {
                    return super.onGetProperty(invoker, receiver, property);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticMethod(dgmBooleanGetterMethod);
                }
            }
        }
        for (SandboxMethodContributor contributor : SandboxMethodContributor.all()) {
            for (Class<?> dgmClass : contributor.getContributedClasses()) {
                final Method dgmGetterMethod = GroovyCallSiteSelector.staticMethod(dgmClass, getter, selfArgs);
                if (dgmGetterMethod != null) {
                    if (whitelist.permitsStaticMethod(dgmGetterMethod, selfArgs)) {
                        try {
                            return dgmGetterMethod.invoke(null, selfArgs);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    } else if (rejector == null) {
                        rejector = () -> StaticWhitelist.rejectStaticMethod(dgmGetterMethod);
                    }
                }
                final Method dgmBooleanGetterMethod = GroovyCallSiteSelector.staticMethod(dgmClass, booleanGetter, selfArgs);
                if (dgmBooleanGetterMethod != null && dgmBooleanGetterMethod.getReturnType() == boolean.class) {
                    if (whitelist.permitsStaticMethod(dgmBooleanGetterMethod, selfArgs)) {
                        try {
                            return dgmBooleanGetterMethod.invoke(null, selfArgs);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    } else if (rejector == null) {
                        rejector = () -> StaticWhitelist.rejectStaticMethod(dgmBooleanGetterMethod);
                    }
                }
            }
        }
        final Field field = GroovyCallSiteSelector.field(receiver, property);
        if (field != null) {
            if (permitsFieldGet(whitelist, field, receiver)) {
                return super.onGetProperty(invoker, receiver, property);
            } else if (rejector == null) {
                rejector = () -> rejectField(field);
            }
        }
        // GroovyObject property access
        Object[] propertyArg = new Object[] {property};
        final Method getPropertyMethod = GroovyCallSiteSelector.method(receiver, "getProperty", propertyArg);
        if (getPropertyMethod != null && !isSyntheticMethod(receiver, getPropertyMethod)) {
            if (whitelist.permitsMethod(getPropertyMethod, receiver, propertyArg)) {
                return super.onGetProperty(invoker, receiver, property);
            } else if (rejector == null) {
                rejector = () -> StaticWhitelist.rejectMethod(getPropertyMethod, receiverClass(receiver).getName() + "." + property);
            }
        }
        if (receiver instanceof Class) {
            final Method staticGetterMethod = GroovyCallSiteSelector.staticMethod((Class) receiver, getter, noArgs);
            if (staticGetterMethod != null) {
                if (whitelist.permitsStaticMethod(staticGetterMethod, noArgs)) {
                    return super.onGetProperty(invoker, receiver, property);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticMethod(staticGetterMethod);
                }
            }
            final Method staticBooleanGetterMethod = GroovyCallSiteSelector.staticMethod((Class) receiver, booleanGetter, noArgs);
            if (staticBooleanGetterMethod != null && staticBooleanGetterMethod.getReturnType() == boolean.class) {
                if (whitelist.permitsStaticMethod(staticBooleanGetterMethod, noArgs)) {
                    return super.onGetProperty(invoker, receiver, property);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticMethod(staticBooleanGetterMethod);
                }
            }
            final Field staticField = GroovyCallSiteSelector.staticField((Class) receiver, property);
            if (staticField != null) {
                if (whitelist.permitsStaticFieldGet(staticField)) {
                    return super.onGetProperty(invoker, receiver, property);
                } else if (rejector == null) {
                    rejector = () -> StaticWhitelist.rejectStaticField(staticField);
                }
            }
        }
        if (mpe != null) {
            throw mpe;
        }
        throw rejector != null ? rejector.reject() : unclassifiedField(receiver, property);
    }

    @Override
    public Object onSuperCall(Invoker invoker, Class senderType, Object receiver, String method, Object... args) throws Throwable {
        Method m = GroovyCallSiteSelector.method(receiver, method, args);
        if (m == null) {
            throw new RejectedAccessException("No such method found: super.method " + EnumeratingWhitelist.getName(receiverClass(receiver)) + " " + method + printArgumentTypes(args));
        } else if (whitelist.permitsMethod(m, receiver, args)) {
            return super.onSuperCall(invoker, senderType, receiver, method, args);
        } else {
            throw StaticWhitelist.rejectMethod(m);
        }
    }

    private static MissingPropertyException unclassifiedField(Object receiver, String property) {
        return new MissingPropertyException("No such field found: field " + EnumeratingWhitelist.getName(receiverClass(receiver)) + " " + property);
    }

    // TODO Java 8: @FunctionalInterface
    private interface Rejector {
        @NonNull RejectedAccessException reject();
    }

    @Override public Object onGetAttribute(Invoker invoker, Object receiver, String attribute) throws Throwable {
        Rejector rejector = null;
        Field field = GroovyCallSiteSelector.field(receiver, attribute);
        if (field != null) {
            if (permitsFieldGet(whitelist, field, receiver)) {
                return super.onGetAttribute(invoker, receiver, attribute);
            } else {
                rejector = () -> rejectField(field);
            }
        }
        if (receiver instanceof Class) {
            Field staticField = GroovyCallSiteSelector.staticField((Class<?>)receiver, attribute);
            if (staticField != null) {
                if (whitelist.permitsStaticFieldGet(staticField)) {
                    return super.onGetAttribute(invoker, receiver, attribute);
                } else {
                    rejector = () -> StaticWhitelist.rejectStaticField(staticField);
                }
            }
        }
        throw rejector != null ? rejector.reject() : unclassifiedField(receiver, attribute);
    }

    @Override public Object onSetAttribute(Invoker invoker, Object receiver, String attribute, Object value) throws Throwable {
        Rejector rejector = null;
        Field field = GroovyCallSiteSelector.field(receiver, attribute);
        if (field != null) {
            if (permitsFieldSet(whitelist, field, receiver, value)) {
                Object snapshotValue = Checker.preCheckedCast(field.getType(), value, false, false, false).call();
                return super.onSetAttribute(invoker, receiver, attribute, snapshotValue);
            } else {
                rejector = () -> rejectField(field);
            }
        }
        if (receiver instanceof Class) {
            Field staticField = GroovyCallSiteSelector.staticField((Class<?>)receiver, attribute);
            if (staticField != null) {
                if (whitelist.permitsStaticFieldSet(staticField, value)) {
                    Object snapshotValue = Checker.preCheckedCast(staticField.getType(), value, false, false, false).call();
                    return super.onSetAttribute(invoker, receiver, attribute, snapshotValue);
                } else {
                    rejector = () -> StaticWhitelist.rejectStaticField(staticField);
                }
            }
        }
        throw rejector != null ? rejector.reject() : unclassifiedField(receiver, attribute);
    }

    @Override public Object onGetArray(Invoker invoker, Object receiver, Object index) throws Throwable {
        if (receiverClass(receiver).isArray() && index instanceof Integer) {
            return super.onGetArray(invoker, receiver, index);
        }
        Object[] args = new Object[] {index};
        Method method = GroovyCallSiteSelector.method(receiver, "getAt", args);
        if (method != null) {
            if (permitsMethod(whitelist, method, receiver, args)) {
                return super.onGetArray(invoker, receiver, index);
            } else {
                throw rejectMethod(method);
            }
        }
        args = new Object[] {receiver, index};
        for (Class<?> dgm : DGM_CLASSES) {
            method = GroovyCallSiteSelector.staticMethod(dgm, "getAt", args);
            if (method != null) {
                if (whitelist.permitsStaticMethod(method, args)) {
                    return super.onGetArray(invoker, receiver, index);
                } else {
                    throw StaticWhitelist.rejectStaticMethod(method);
                }
            }
        }
        throw new RejectedAccessException("No such getAt method found: method " + EnumeratingWhitelist.getName(receiver) + "[" + EnumeratingWhitelist.getName(index) + "]");
    }

    @Override public Object onSetArray(Invoker invoker, Object receiver, Object index, Object value) throws Throwable {
        if (receiverClass(receiver).isArray() && index instanceof Integer) {
            return super.onSetArray(invoker, receiver, index, value);
        }
        Object[] args = new Object[] {index, value};
        Method method = GroovyCallSiteSelector.method(receiver, "putAt", args);
        if (method != null) {
            if (permitsMethod(whitelist, method, receiver, args)) {
                return super.onSetArray(invoker, receiver, index, value);
            } else {
                throw rejectMethod(method);
            }
        }
        args = new Object[] {receiver, index, value};
        for (Class<?> dgm : DGM_CLASSES) {
            method = GroovyCallSiteSelector.staticMethod(dgm, "putAt", args);
            if (method != null) {
                if (whitelist.permitsStaticMethod(method, args)) {
                    return super.onSetArray(invoker, receiver, index, value);
                } else {
                    throw StaticWhitelist.rejectStaticMethod(method);
                }
            }
        }
        throw new RejectedAccessException("No such putAt method found: putAt method " + EnumeratingWhitelist.getName(receiver) + "[" + EnumeratingWhitelist.getName(index) + "]=" + EnumeratingWhitelist.getName(value));
    }

    private static void preCheckArgumentCasts(Method method, Object[] args) throws Throwable {
        Parameter[] parameters = method.getParameters();
        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            if (i == parameters.length - 1 && parameter.isVarArgs()) {
                Class<?> componentType = parameter.getType().getComponentType();
                for (int j = i; j < args.length; j++) {
                    args[j] = Checker.preCheckedCast(componentType, args[j], false, false, false).call();
                }
            } else {
                args[i] = Checker.preCheckedCast(parameter.getType(), args[i], false, false, false).call();
            }
        }
    }

    /**
     * Check if the specified method defined on the receiver is synthetic.
     *
     * If {@code receiver} is a {@link GroovyObject} with a synthetically generated implementation of
     * {@link GroovyObject#getProperty} or {@link GroovyObject#setProperty}, then we do not care about intercepting
     * that method call since we handle known cases, and we specifically do not want missing properties to be rejected
     * because of the existence of the method.
     */
    private static boolean isSyntheticMethod(Object receiver, Method method) {
        try {
            return receiverClass(receiver).getDeclaredMethod(method.getName(), String.class, Object.class).isSynthetic();
        } catch (NoSuchMethodException e) {
            // Some unusual case, e.g. the method is defined in a superclass, so we return false and intercept the call just in case.
        }
        return false;
    }

    private static String printArgumentTypes(Object[] args) {
        StringBuilder b = new StringBuilder();
        for (Object arg : args) {
            b.append(' ');
            b.append(EnumeratingWhitelist.getName(arg));
        }
        return b.toString();
    }

    private static @CheckForNull MetaMethod findMetaMethod(@CheckForNull Object receiver, @NonNull String method, @NonNull Object[] args) {
        if (receiver == null) return null;
        Class<?>[] types = new Class[args.length];
        for (int i = 0; i < types.length; i++) {
            Object arg = args[i];
            types[i] = arg == null ? /* is this right? */void.class : arg.getClass();
        }
        try {
            return DefaultGroovyMethods.getMetaClass(receiver).pickMethod(method, types);
        } catch (GroovyRuntimeException x) { // ambiguous call, supposedly
            LOGGER.log(Level.FINE, "could not find metamethod for " + receiverClass(receiver) + "." + method + Arrays.toString(types), x);
            return null;
        }
    }

    private static boolean permitsFieldGet(@NonNull Whitelist whitelist, @NonNull Field field, @CheckForNull Object receiver) {
        if (Modifier.isStatic(field.getModifiers())) {
            return whitelist.permitsStaticFieldGet(field);
        }
        return whitelist.permitsFieldGet(field, receiver == null ? NullObject.getNullObject() : receiver);
    }

    private static boolean permitsFieldSet(@NonNull Whitelist whitelist, @NonNull Field field, @CheckForNull Object receiver, @CheckForNull Object value) {
        if (Modifier.isStatic(field.getModifiers())) {
            return whitelist.permitsStaticFieldSet(field, value);
        }
        return whitelist.permitsFieldSet(field, receiver == null ? NullObject.getNullObject() : receiver, value);
    }

    private static boolean permitsMethod(@NonNull Whitelist whitelist, @NonNull Method method, @CheckForNull Object receiver, @NonNull Object[] args) {
        if (Modifier.isStatic(method.getModifiers())) {
            return whitelist.permitsStaticMethod(method, args);
        }
        return whitelist.permitsMethod(method, receiver == null ? NullObject.getNullObject() : receiver, args);
    }

    public static RejectedAccessException rejectMethod(@NonNull Method m) {
        if (Modifier.isStatic(m.getModifiers())) {
            return StaticWhitelist.rejectStaticMethod(m);
        }
        return StaticWhitelist.rejectMethod(m);
    }

    public static RejectedAccessException rejectField(@NonNull Field f) {
        if (Modifier.isStatic(f.getModifiers())) {
            return StaticWhitelist.rejectStaticField(f);
        }
        return StaticWhitelist.rejectField(f);
    }

}
