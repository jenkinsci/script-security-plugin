package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import groovy.lang.GroovyShell;
import java.net.URL;
import java.util.concurrent.TimeUnit;
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

    @SuppressWarnings("rawtypes")
    private static final LoadingCache<ClassLoader, LoadingCache<String, Optional<Class>>> parentClassCache = makeParentCache(new CacheFunction<Optional<Class>>() {
        @Override public Optional<Class> compute(ClassLoader parentLoader, String name) {
            try {
                Class c = parentLoader.loadClass(name);
                return Optional.of(c);
            } catch (ClassNotFoundException x) {
                return Optional.absent();
            }
        }
    });

    private static final LoadingCache<ClassLoader, LoadingCache<String, Optional<URL>>> parentResourceCache = makeParentCache(new CacheFunction<Optional<URL>>() {
        @Override public Optional<URL> compute(ClassLoader parentLoader, String name) {
            return Optional.fromNullable(parentLoader.getResource(name));
        }
    });

    SandboxResolvingClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.kohsuke.groovy.sandbox.")) {
            return this.getClass().getClassLoader().loadClass(name);
        } else {
            Class<?> c = parentClassCache.getUnchecked(getParent()).getUnchecked(name).orNull();
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
        return parentResourceCache.getUnchecked(getParent()).getUnchecked(name).orNull();
    }

    private interface CacheFunction<T> {
        T compute(ClassLoader parentLoader, String name);
    }

    private static <T> LoadingCache<ClassLoader, LoadingCache<String, T>> makeParentCache(final CacheFunction<T> function) {
        return CacheBuilder.newBuilder().weakKeys().build(new CacheLoader<ClassLoader,LoadingCache<String, T>>() {
            @Override public LoadingCache<String, T> load(final ClassLoader parentLoader) {
                return CacheBuilder.newBuilder()./* allow new plugins to be used, and clean up memory */expireAfterWrite(15, TimeUnit.MINUTES).build(new CacheLoader<String, T>() {
                    @Override public T load(String name) {
                        Thread t = Thread.currentThread();
                        String origName = t.getName();
                        t.setName(origName + " loading " + name);
                        long start = System.nanoTime(); // http://stackoverflow.com/q/19052316/12916
                        try {
                            return function.compute(parentLoader, name);
                        } finally {
                            t.setName(origName);
                            long ms = (System.nanoTime() - start) / 1000000;
                            if (ms > 1000) {
                                LOGGER.log(Level.INFO, "took {0}ms to load/not load {1} from {2}", new Object[] {ms, name, parentLoader});
                            }
                        }
                    }
                });
            }
        });
    }

}
