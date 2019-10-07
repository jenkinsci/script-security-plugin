package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import groovy.lang.GroovyShell;
import java.lang.ref.WeakReference;
import java.net.URL;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
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

    static final LoadingCache<ClassLoader, AsyncCache<String, WeakReference<Class<?>>>> parentClassCache = makeParentCache();

    static final LoadingCache<ClassLoader, AsyncCache<String, Optional<URL>>> parentResourceCache = makeParentCache();

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
    static final Class<?> CLASS_NOT_FOUND = Unused.class;
    private static final class Unused {}

    @Override protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.kohsuke.groovy.sandbox.")) {
            return this.getClass().getClassLoader().loadClass(name);
        } else {
            ClassLoader parentLoader = getParent();
            Future<WeakReference<Class<?>>> future = load(parentClassCache, name, parentLoader, () -> {
                try {
                    return new WeakReference<>(parentLoader.loadClass(name));
                } catch (ClassNotFoundException x) {
                    return new WeakReference<>(CLASS_NOT_FOUND);
                }
            });
            Thread t = Thread.currentThread();
            String origName = t.getName();
            t.setName(origName + " loading " + name);
            try {
                Class<?> c = future.get().get();
                if (c != CLASS_NOT_FOUND) {
                    if (resolve) {
                        super.resolveClass(c);
                    }
                    return c;
                } else {
                    throw new StacklessClassNotFoundException(name);
                }
            } catch (ExecutionException e) {
                throw new StacklessClassNotFoundException(name, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new StacklessClassNotFoundException(name, e);
            } finally {
                t.setName(origName);
            }
        }
    }

    @Override public URL getResource(String name) {
        ClassLoader parentLoader = getParent();
        Future<Optional<URL>> future = load(parentResourceCache, name, parentLoader, () -> Optional.ofNullable(parentLoader.getResource(name)));
        try {
            return future.get().orElse(null);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    // We cannot have the inner cache be a LoadingCache and just use .get(name), since then the values of the outer cache would strongly refer to the keys.
    private static <T> Future<T> load(LoadingCache<ClassLoader, AsyncCache<String, T>> cache, String name, ClassLoader parentLoader, Supplier<T> supplier) {
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

    private static <T> LoadingCache<ClassLoader, AsyncCache<String, T>> makeParentCache() {
        // The outer cache has weak keys, so that we do not leak class loaders, but strong values, because the
        // inner caches are only referenced by the outer cache internally.
        Caffeine<Object, Object> outerBuilder = Caffeine.newBuilder().recordStats().weakKeys();
        // The inner cache has strong keys, since they are just strings, and expires entries 15 minutes after they are
        // added to the cache, so that classes defined by dynamically installed plugins become available even if there
        // were negative cache hits prior to the installation (ideally this would be done with a listener).
        Caffeine<Object, Object> innerBuilder = Caffeine.newBuilder().recordStats().expireAfterWrite(Duration.ofMinutes(15));

        return outerBuilder.build(parentLoader -> innerBuilder.buildAsync());
    }

    private static class StacklessClassNotFoundException extends java.lang.ClassNotFoundException {
        public StacklessClassNotFoundException(String message) {
            super(message);
        }

        public StacklessClassNotFoundException(String message, Throwable cause) {
            super(message, cause);
        }

        @Override public synchronized Throwable fillInStackTrace() {
            return this; // super call is too expensive
        }
    }
}
