/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.Binding;
import groovy.lang.GroovyClassLoader;
import groovy.lang.GroovyShell;
import hudson.Extension;
import hudson.PluginManager;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.util.FormValidation;

import java.beans.Introspector;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import jenkins.model.Jenkins;
import org.codehaus.groovy.control.CompilationFailedException;
import org.codehaus.groovy.control.CompilationUnit;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.SourceUnit;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.scripts.ApprovalContext;
import org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedClasspathException;
import org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Convenience structure encapsulating a Groovy script that may either be approved whole or sandboxed.
 * May be kept as the value of a field and passed in a {@link DataBoundConstructor} parameter;
 * you <strong>must</strong> call {@link #configuring} or a related method from your own constructor.
 * Use {@code <f:property field="…"/>} to configure it from Jelly.
 */
public final class SecureGroovyScript extends AbstractDescribableImpl<SecureGroovyScript> {
 
    private final @Nonnull String script;
    private final boolean sandbox;
    private final @CheckForNull List<ClasspathEntry> classpath;
    private transient boolean calledConfiguring;

    static final Logger LOGGER = Logger.getLogger(SecureGroovyScript.class.getName());

    @DataBoundConstructor public SecureGroovyScript(@Nonnull String script, boolean sandbox, @CheckForNull List<ClasspathEntry> classpath) {
        this.script = script;
        this.sandbox = sandbox;
        this.classpath = classpath;
    }

    @Deprecated public SecureGroovyScript(@Nonnull String script, boolean sandbox) {
        this(script, sandbox, null);
    }

    private Object readResolve() {
        configuring(ApprovalContext.create());
        return this;
    }

    public @Nonnull String getScript() {
        return script;
    }

    public boolean isSandbox() {
        return sandbox;
    }

    public @Nonnull List<ClasspathEntry> getClasspath() {
        return classpath != null ? classpath : Collections.<ClasspathEntry>emptyList();
    }

    /**
     * To be called in your own {@link DataBoundConstructor} when storing the field of this type.
     * @param context an approval context
     * @return this object
     */
    public SecureGroovyScript configuring(ApprovalContext context) {
        calledConfiguring = true;
        if (!sandbox) {
            ScriptApproval.get().configuring(script, GroovyLanguage.get(), context);
        }
        for (ClasspathEntry entry : getClasspath()) {
            ScriptApproval.get().configuring(entry, context);
        }
        return this;
    }

    private static @CheckForNull Item currentItem() {
        StaplerRequest req = Stapler.getCurrentRequest();
        return req != null ? req.findAncestorObject(Item.class) : null;
    }

    /** Convenience form of {@link #configuring} that calls {@link ApprovalContext#withCurrentUser} and {@link ApprovalContext#withItemAsKey}. */
    public SecureGroovyScript configuringWithKeyItem() {
        ApprovalContext context = ApprovalContext.create();
        context = context.withCurrentUser().withItemAsKey(currentItem());
        return configuring(context);
    }

    /** Convenience form of {@link #configuring} that calls {@link ApprovalContext#withCurrentUser} and {@link ApprovalContext#withItem}. */
    public SecureGroovyScript configuringWithNonKeyItem() {
        ApprovalContext context = ApprovalContext.create();
        context = context.withCurrentUser().withItem(currentItem());
        return configuring(context);
    }

    private static void cleanUpLoader(ClassLoader loader, Set<ClassLoader> encounteredLoaders, Set<Class<?>> encounteredClasses) throws Exception {
        /*if (loader instanceof CpsGroovyShell.TimingLoader) {
            cleanUpLoader(loader.getParent(), encounteredLoaders, encounteredClasses);
            return;
        }*/
        // Check me, am I cleaning up the right loader???
        if (!(loader instanceof GroovyClassLoader)) {
            LOGGER.log(Level.FINER, "ignoring {0}", loader);
            return;
        }
        if (!encounteredLoaders.add(loader)) {
            return;
        }
        cleanUpLoader(loader.getParent(), encounteredLoaders, encounteredClasses);
        if (LOGGER.isLoggable(Level.FINER)) {
          LOGGER.log(Level.FINER, "found {0}", String.valueOf(loader));
        }
        cleanUpGlobalClassValue(loader);
        GroovyClassLoader gcl = (GroovyClassLoader) loader;
        for (Class<?> clazz : gcl.getLoadedClasses()) {
            if (encounteredClasses.add(clazz)) {
                LOGGER.log(Level.FINER, "found {0}", clazz.getName());
                Introspector.flushFromCaches(clazz);
                cleanUpGlobalClassSet(clazz);
                cleanUpObjectStreamClassCaches(clazz);
                cleanUpLoader(clazz.getClassLoader(), encounteredLoaders, encounteredClasses);
            }
        }
        gcl.clearCache();
    }

    private static void cleanUpGlobalClassValue(@Nonnull ClassLoader loader) throws Exception {
        Class<?> classInfoC = Class.forName("org.codehaus.groovy.reflection.ClassInfo");
        // TODO switch to MethodHandle for speed
        Field globalClassValueF = classInfoC.getDeclaredField("globalClassValue");
        globalClassValueF.setAccessible(true);
        Object globalClassValue = globalClassValueF.get(null);
        Class<?> groovyClassValuePreJava7C = Class.forName("org.codehaus.groovy.reflection.GroovyClassValuePreJava7");
        if (!groovyClassValuePreJava7C.isInstance(globalClassValue)) {
            return; // using GroovyClassValueJava7 due to -Dgroovy.use.classvalue or on IBM J9, fine
        }
        Field mapF = groovyClassValuePreJava7C.getDeclaredField("map");
        mapF.setAccessible(true);
        Object map = mapF.get(globalClassValue);
        Class<?> groovyClassValuePreJava7Map = Class.forName("org.codehaus.groovy.reflection.GroovyClassValuePreJava7$GroovyClassValuePreJava7Map");
        Collection entries = (Collection) groovyClassValuePreJava7Map.getMethod("values").invoke(map);
        Method removeM = groovyClassValuePreJava7Map.getMethod("remove", Object.class);
        Class<?> entryC = Class.forName("org.codehaus.groovy.util.AbstractConcurrentMapBase$Entry");
        Method getValueM = entryC.getMethod("getValue");
        List<Class<?>> toRemove = new ArrayList<>(); // not sure if it is safe against ConcurrentModificationException or not
        try {
            Field classRefF = classInfoC.getDeclaredField("classRef"); // 2.4.8+
            classRefF.setAccessible(true);
            for (Object entry : entries) {
                Object value = getValueM.invoke(entry);
                toRemove.add(((WeakReference<Class<?>>) classRefF.get(value)).get());
            }
        } catch (NoSuchFieldException x) {
            Field klazzF = classInfoC.getDeclaredField("klazz"); // 2.4.7-
            klazzF.setAccessible(true);
            for (Object entry : entries) {
                Object value = getValueM.invoke(entry);
                toRemove.add((Class) klazzF.get(value));
            }
        }
        Iterator<Class<?>> it = toRemove.iterator();
        while (it.hasNext()) {
            Class<?> klazz = it.next();
            ClassLoader encounteredLoader = klazz.getClassLoader();
            if (encounteredLoader != loader) {
                it.remove();
                if (LOGGER.isLoggable(Level.FINEST)) {
                  LOGGER.log(Level.FINEST, "ignoring {0} with loader {1}", new Object[] {klazz, /* do not hold from LogRecord */String.valueOf(encounteredLoader)});
                }
            }
        }
        LOGGER.log(Level.FINE, "cleaning up {0} associated with {1}", new Object[] {toRemove.toString(), loader.toString()});
        for (Class<?> klazz : toRemove) {
            removeM.invoke(map, klazz);
        }
    }

    private static void cleanUpGlobalClassSet(@Nonnull Class<?> clazz) throws Exception {
        Class<?> classInfoC = Class.forName("org.codehaus.groovy.reflection.ClassInfo"); // or just ClassInfo.class, but unclear whether this will always be there
        Field globalClassSetF = classInfoC.getDeclaredField("globalClassSet");
        globalClassSetF.setAccessible(true);
        Object globalClassSet = globalClassSetF.get(null);
        try {
            classInfoC.getDeclaredField("classRef");
            return; // 2.4.8+, nothing to do here (classRef is weak anyway)
        } catch (NoSuchFieldException x2) {} // 2.4.7-
        // Cannot just call .values() since that returns a copy.
        Field itemsF = globalClassSet.getClass().getDeclaredField("items");
        itemsF.setAccessible(true);
        Object items = itemsF.get(globalClassSet);
        Method iteratorM = items.getClass().getMethod("iterator");
        Field klazzF = classInfoC.getDeclaredField("klazz");
        klazzF.setAccessible(true);
        synchronized (items) {
            Iterator<?> iterator = (Iterator) iteratorM.invoke(items);
            while (iterator.hasNext()) {
                Object classInfo = iterator.next();
                if (classInfo == null) {
                    LOGGER.finer("JENKINS-41945: ignoring null ClassInfo from ManagedLinkedList.Iter.next");
                    continue;
                }
                if (klazzF.get(classInfo) == clazz) {
                    iterator.remove();
                    LOGGER.log(Level.FINER, "cleaning up {0} from GlobalClassSet", clazz.getName());
                }
            }
        }
    }

    private static void cleanUpObjectStreamClassCaches(@Nonnull Class<?> clazz) throws Exception {
        Class<?> cachesC = Class.forName("java.io.ObjectStreamClass$Caches");
        for (String cacheFName : new String[] {"localDescs", "reflectors"}) {
            Field cacheF = cachesC.getDeclaredField(cacheFName);
            cacheF.setAccessible(true);
            ConcurrentMap<Reference<Class<?>>, ?> cache = (ConcurrentMap) cacheF.get(null);
            Iterator<? extends Map.Entry<Reference<Class<?>>, ?>> iterator = cache.entrySet().iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getKey().get() == clazz) {
                    iterator.remove();
                    if (LOGGER.isLoggable(Level.FINER)) {
                      LOGGER.log(Level.FINER, "cleaning up {0} from ObjectStreamClass.Caches.{1}", new Object[] {clazz.getName(), cacheFName});
                    }
                    break;
                }
            }
        }
    }

    /**
     * Runs the Groovy script, using the sandbox if so configured.
     * @param loader a class loader for constructing the shell, such as {@link PluginManager#uberClassLoader} (will be augmented by {@link #getClasspath} if nonempty)
     * @param binding Groovy variable bindings
     * @return the result of evaluating script using {@link GroovyShell#evaluate(String)}
     * @throws Exception in case of a general problem
     * @throws RejectedAccessException in case of a sandbox issue
     * @throws UnapprovedUsageException in case of a non-sandbox issue
     * @throws UnapprovedClasspathException in case some unapproved classpath entries were requested
     */
    @SuppressFBWarnings(value = "DP_CREATE_CLASSLOADER_INSIDE_DO_PRIVILEGED", justification = "Managed by GroovyShell.")
    public Object evaluate(ClassLoader loader, Binding binding) throws Exception {
        if (!calledConfiguring) {
            throw new IllegalStateException("you need to call configuring or a related method before using GroovyScript");
        }
        URLClassLoader urlcl = null;
        ClassLoader memoryProtectedLoader = null;
        List<ClasspathEntry> cp = getClasspath();
        if (!cp.isEmpty()) {
            List<URL> urlList = new ArrayList<URL>(cp.size());
            
            for (ClasspathEntry entry : cp) {
                ScriptApproval.get().using(entry);
                urlList.add(entry.getURL());
            }
            
            loader = urlcl = new URLClassLoader(urlList.toArray(new URL[urlList.size()]), loader);
        }
        boolean canDoCleanup = false;

        try {
            loader = GroovySandbox.createSecureClassLoader(loader);

            Field loaderF = null;
            try {
                loaderF = GroovyShell.class.getDeclaredField("loader");
                loaderF.setAccessible(true);
                canDoCleanup = true;
            } catch (NoSuchFieldException nsme) {
                LOGGER.log(Level.FINE, "GroovyShell fields have changed, field loader no longer exists -- memory leak fixes won't work");
            }

            GroovyShell sh;
            if (sandbox) {
                CompilerConfiguration cc = GroovySandbox.createSecureCompilerConfiguration();
                sh = new GroovyShell(loader, binding, cc);

                if (canDoCleanup) {
                    memoryProtectedLoader = new CleanGroovyClassLoader(loader, cc);
                    loaderF.set(sh, memoryProtectedLoader);
                }

                try {
                    return GroovySandbox.run(sh.parse(script), Whitelist.all());
                } catch (RejectedAccessException x) {
                    throw ScriptApproval.get().accessRejected(x, ApprovalContext.create());
                }
            } else {
                sh = new GroovyShell(loader, binding);
                if (canDoCleanup) {
                    memoryProtectedLoader = new CleanGroovyClassLoader(loader);
                    loaderF.set(sh, memoryProtectedLoader);
                }
                return sh.evaluate(ScriptApproval.get().using(script, GroovyLanguage.get()));
            }

        } finally {
            try {
                if (canDoCleanup) {
                    cleanUpLoader(memoryProtectedLoader, new HashSet<ClassLoader>(), new HashSet<Class<?>>());
                }
            } catch (Exception x) {
                LOGGER.log(Level.WARNING, "failed to clean up memory " , x);
            }

            if (urlcl != null) {
                urlcl.close();
            }
        }
    }


    /**
     * Disables the weird and unreliable {@link groovy.lang.GroovyClassLoader.InnerLoader}.
     * This is apparently only necessary when you are using class recompilation, which we are not.
     * We want the {@linkplain Class#getClassLoader defining loader} of {@code *.groovy} to be this one.
     * Otherwise the defining loader will be an {@code InnerLoader}, and not necessarily the same instance from load to load.
     * @see GroovyClassLoader#getTimeStamp
     */
    private static final class CleanGroovyClassLoader extends GroovyClassLoader {

        CleanGroovyClassLoader(ClassLoader loader, CompilerConfiguration config) {
            super(loader, config);
        }

        CleanGroovyClassLoader(ClassLoader loader) {
            super(loader);
        }

        @Override protected ClassCollector createCollector(CompilationUnit unit, SourceUnit su) {
            // Super implementation is what creates the InnerLoader.
            return new CleanClassCollector(unit, su);
        }

        private final class CleanClassCollector extends ClassCollector {

            CleanClassCollector(CompilationUnit unit, SourceUnit su) {
                // Cannot override {@code final cl} field so have to do it this way.
                super(null, unit, su);
            }

            @Override public GroovyClassLoader getDefiningClassLoader() {
                return CleanGroovyClassLoader.this;
            }

        }
    }

    @Extension public static final class DescriptorImpl extends Descriptor<SecureGroovyScript> {

        @Override public String getDisplayName() {
            return ""; // not intended to be displayed on its own
        }

        public FormValidation doCheckScript(@QueryParameter String value, @QueryParameter boolean sandbox) {
            try {
                new GroovyShell(Jenkins.getInstance().getPluginManager().uberClassLoader).parse(value);
            } catch (CompilationFailedException x) {
                return FormValidation.error(x.getLocalizedMessage());
            }
            return sandbox ? FormValidation.ok() : ScriptApproval.get().checking(value, GroovyLanguage.get());
        }

    }

}
