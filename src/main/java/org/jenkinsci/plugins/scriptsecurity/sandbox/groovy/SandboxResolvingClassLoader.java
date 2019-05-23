package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.google.common.base.Optional;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import groovy.lang.GroovyShell;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Makes sure that the class references to groovy-sandbox resolves to our own copy of
 * <tt>groovy-sandbox.jar</tt> instead of the random one picked up by the classloader
 * given to {@link GroovyShell} via the constructor.
 * <p>Also tries to cache parent class loading calls, to work around various issues including lack of parallelism.
 * @see <a href="https://issues.jenkins-ci.org/browse/JENKINS-25348">JENKINS-25438</a>
 * @see <a href="https://issues.jenkins-ci.org/browse/JENKINS-23784">JENKINS-23784</a>
 */
class SandboxResolvingClassLoader extends ClassLoader {
    
    private static final Logger LOGGER = Logger.getLogger(SandboxResolvingClassLoader.class.getName());

    private static final LoadingCache<ClassLoader, Cache<String, Optional<Class<?>>>> parentClassCache = makeParentCache();

    private static final LoadingCache<ClassLoader, Cache<String, Optional<URL>>> parentResourceCache = makeParentCache();

    SandboxResolvingClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.kohsuke.groovy.sandbox.")) {
            return this.getClass().getClassLoader().loadClass(name);
        } else {
            ClassLoader parentLoader = getParent();
            Class<?> c = load(parentClassCache, name, parentLoader, () -> {
                try {
                    return Optional.of(parentLoader.loadClass(name));
                } catch (ClassNotFoundException x) {
                    return Optional.absent();
                }
            }).orNull();
            if (c != null) {
                if (resolve) {
                    super.resolveClass(c);
                }
                return c;
            } else {
                throw new ClassNotFoundException(name) {
                    @Override public synchronized Throwable fillInStackTrace() {
                        return this; // super call is too expensive
                    }
                };
            }
        }
    }

    @Override public URL getResource(String name) {
        ClassLoader parentLoader = getParent();
        return load(parentResourceCache, name, parentLoader, () -> Optional.fromNullable(parentLoader.getResource(name))).orNull();
    }

    // We cannot have the inner cache be a LoadingCache and just use .get(name), since then the values of the outer cache would strongly refer to the keys.
    private static <T> T load(LoadingCache<ClassLoader, Cache<String, T>> cache, String name, ClassLoader parentLoader, Supplier<T> supplier) {
        try {
            return cache.getUnchecked(parentLoader).get(name, () -> {
                Thread t = Thread.currentThread();
                String origName = t.getName();
                t.setName(origName + " loading " + name);
                long start = System.nanoTime(); // http://stackoverflow.com/q/19052316/12916
                try {
                    return supplier.get();
                } finally {
                    t.setName(origName);
                    long ms = (System.nanoTime() - start) / 1000000;
                    if (ms > 1000) {
                        LOGGER.log(Level.INFO, "took {0}ms to load/not load {1} from {2}", new Object[] {ms, name, parentLoader});
                    }
                }
            });
        } catch (ExecutionException x) {
            throw new UncheckedExecutionException(x); // should not be possible anyway
        }
    }

    private static <T> LoadingCache<ClassLoader, Cache<String, T>> makeParentCache() {
        return CacheBuilder.newBuilder().weakKeys().build(new CacheLoader<ClassLoader, Cache<String, T>>() {
            @Override public Cache<String, T> load(ClassLoader parentLoader) {
                return CacheBuilder.newBuilder()./* allow new plugins to be used, and clean up memory */expireAfterWrite(15, TimeUnit.MINUTES).build();
            }
        });
    }

}
