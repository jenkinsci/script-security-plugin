package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import groovy.lang.GroovyShell;
import java.net.URL;
import java.util.function.BiFunction;
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

    private static final ClassLoaderCache<LoadingCache<String, Optional<Class<?>>>> parentClassCache = makeParentCache((parentLoader, name) -> {
        try {
            return Optional.of(parentLoader.loadClass(name));
        } catch (ClassNotFoundException x) {
            return Optional.absent();
        }
    });

    private static final ClassLoaderCache<LoadingCache<String, Optional<URL>>> parentResourceCache = makeParentCache((parentLoader, name) -> Optional.fromNullable(parentLoader.getResource(name)));

    SandboxResolvingClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.kohsuke.groovy.sandbox.")) {
            return this.getClass().getClassLoader().loadClass(name);
        } else {
            Class<?> c = parentClassCache.get(getParent()).getUnchecked(name).orNull();
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
        return parentResourceCache.get(getParent()).getUnchecked(name).orNull();
    }

    private static <T> ClassLoaderCache<LoadingCache<String, T>> makeParentCache(BiFunction<ClassLoader, String, T> func) {
        // TODO expire cache if new plugins are installed
        return new ClassLoaderCache<>(parentLoader -> {
            return CacheBuilder.newBuilder().build(new CacheLoader<String, T>() {
                @Override public T load(String name) throws Exception {
                    Thread t = Thread.currentThread();
                    String origName = t.getName();
                    t.setName(origName + " loading " + name);
                    long start = System.nanoTime(); // http://stackoverflow.com/q/19052316/12916
                    try {
                        return func.apply(parentLoader, name);
                    } finally {
                        t.setName(origName);
                        long ms = (System.nanoTime() - start) / 1000000;
                        if (ms > 1000) {
                            LOGGER.log(Level.INFO, "took {0}ms to load/not load {1} from {2}", new Object[] {ms, name, parentLoader});
                        }
                    }
                }
            });
        });
    }

}
