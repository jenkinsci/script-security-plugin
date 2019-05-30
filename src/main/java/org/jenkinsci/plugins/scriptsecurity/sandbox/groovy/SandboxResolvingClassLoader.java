package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.base.Optional;
import com.google.common.base.Supplier;
import groovy.lang.GroovyShell;
import java.net.URL;
import java.time.Duration;
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

    private static final LoadingCache<ClassLoader, Cache<String, Class<?>>> parentClassCache = makeParentCache(true);

    private static final LoadingCache<ClassLoader, Cache<String, Optional<URL>>> parentResourceCache = makeParentCache(false);

    SandboxResolvingClassLoader(ClassLoader parent) {
        super(parent);
    }

    /**
     * Marker value for a {@link ClassNotFoundException} negative cache hit.
     * Cannot use null, since the cache API does not permit null values.
     * Cannot use {@code Optional<Class<?>>} since weak values would mean this is always collected.
     * This value is non-null, not a legitimate return value
     * (no script should be trying to load this implementation detail), and strongly held.
     */
    private static final Class<?> CLASS_NOT_FOUND = Unused.class;
    private static final class Unused {}

    @Override protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.kohsuke.groovy.sandbox.")) {
            return this.getClass().getClassLoader().loadClass(name);
        } else {
            ClassLoader parentLoader = getParent();
            Class<?> c = load(parentClassCache, name, parentLoader, () -> {
                try {
                    return parentLoader.loadClass(name);
                } catch (ClassNotFoundException x) {
                    return CLASS_NOT_FOUND;
                }
            });
            if (c != CLASS_NOT_FOUND) {
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
        // itemName is ignored but caffeine requires a function<String, T>
        return cache.get(parentLoader).get(name, (String itemName) -> {
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
    }

    private static <T> LoadingCache<ClassLoader, Cache<String, T>> makeParentCache(boolean weakValues) {
        Caffeine<Object, Object> builder = Caffeine.newBuilder().weakKeys();
        if (weakValues) {
            builder = builder.weakValues();
        }

        return builder.build(parentLoader -> Caffeine.newBuilder()./* allow new plugins to be used, and clean up memory */expireAfterWrite(Duration.ofMinutes(15)).build());
    }
}
