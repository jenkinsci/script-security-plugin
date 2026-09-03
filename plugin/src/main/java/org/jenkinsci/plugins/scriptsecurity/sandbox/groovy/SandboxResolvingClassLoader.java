package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Scheduler;
import groovy.lang.GroovyClassLoader;
import groovy.lang.GroovyShell;
import hudson.util.ClassLoaderSanityThreadFactory;
import hudson.util.DaemonThreadFactory;
import hudson.util.NamingThreadFactory;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.ProtectionDomain;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinWorkerThread;
import java.util.concurrent.ThreadFactory;
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

    /**
     * Care must be taken to avoid leaking instances of {@link GroovyClassLoader} when computing the cached value.
     * This can happen in several ways, depending on the Caffeine configuration:
     *
     * <ul>
     *   <li>In its default configuration, Caffeine uses {@link ForkJoinPool#commonPool} as its {@link Executor}.
     *       As of recent Java versions, {@link ForkJoinPool} can capture a reference to {@link GroovyClassLoader} by
     *       creating a {@link ForkJoinWorkerThread} whose {@link Thread#inheritedAccessControlContext} refers to an
     *       {@link AccessControlContext} whose {@link ProtectionDomain} refers to {@link GroovyClassLoader}.
     *   <li>When Caffeine is configured with an {@link Executor} returned by {@link Executors#newCachedThreadPool},
     *       that {@link Executor} can capture a reference to {@link GroovyClassLoader} by creating a {@link Thread}
     *       whose {@link Thread#inheritedAccessControlContext} refers to an {@link AccessControlContext} whose {@link
     *       ProtectionDomain} refers to {@link GroovyClassLoader}. Additionally, when the thread pool's {@link
     *       ThreadFactory} is not wrapped by {@link ClassLoaderSanityThreadFactory}, the {@link Executor} can sometimes
     *       create {@link Thread} instances whose {@link Thread#contextClassLoader} refers to {@link
     *       GroovyClassLoader}.
     * </ul>
     *
     * As of <a href="https://openjdk.org/jeps/411">JEP-411</a>, {@link Thread#inheritedAccessControlContext} is
     * deprecated for removal, but in the meantime we must contend with this issue. We therefore create a dedicated
     * {@link Executors#newSingleThreadExecutor}, which is safe for use with Caffeine from a memory perspective because:
     *
     * <ul>
     *   <li>In contrast to {@link ForkJoinPool#commonPool}, the thread is eagerly created and avoids references to
     *       {@link GroovyClassLoader} in {@link Thread#inheritedAccessControlContext}.
     *   <li>In contrast to {@link Executors#newCachedThreadPool}, the thread is eagerly created and avoids references
     *       to {@link GroovyClassLoader} in {@link Thread#inheritedAccessControlContext}.
     *   <li>In contrast to {@link Executors#newCachedThreadPool}, the thread is eagerly created and avoids references
     *       to {@link GroovyClassLoader} in {@link Thread#contextClassLoader}, thereby avoiding the need for {@link
     *       ClassLoaderSanityThreadFactory}.
     * </ul>
     *
     * A single-threaded {@link Executor} is safe for use with Caffeine from a CPU perspective because <a
     * href="https://stackoverflow.com/a/68105121">the cache's work is implemented with cheap O(1) algorithms</a>.
     *
     * <p>In the medium term, once {@link Thread#inheritedAccessControlContext} is removed upstream, we could possibly
     * switch to a combination of {@link Executors#newCachedThreadPool} and {@link ClassLoaderSanityThreadFactory}.
     *
     * <p>In the long term, a listener should be added to inform this class when dynamically installed plugins become
     * available, as described in the comments to {@link #makeParentCache(boolean)}, in which case the use of Caffeine
     * could possibly be removed entirely.
     */
    private static final Executor cacheExecutor = Executors.newSingleThreadExecutor(new NamingThreadFactory(
            new DaemonThreadFactory(), SandboxResolvingClassLoader.class.getName() + ".cacheExecutor"));

    static final LoadingCache<ClassLoader, Cache<String, Class<?>>> parentClassCache = makeParentCache(true);

    static final LoadingCache<ClassLoader, Cache<String, Optional<URL>>> parentResourceCache = makeParentCache(false);

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
        return load(parentResourceCache, name, parentLoader, () -> Optional.ofNullable(parentLoader.getResource(name))).orElse(null);
    }

    // We cannot have the inner cache be a LoadingCache and just use .get(name), since then the values of the outer cache would strongly refer to the keys.
    private static <T> T load(LoadingCache<ClassLoader, Cache<String, T>> cache, String name, ClassLoader parentLoader, Supplier<T> supplier) {
        Cache<String, T> classCache = cache.get(parentLoader);
        assert classCache != null; // Never null, see makeParentCache, but we need the assertion to convince SpotBugs.
        // itemName is ignored but caffeine requires a function<String, T>
        return classCache.get(name, (String itemName) -> {
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

    private static <T> LoadingCache<ClassLoader, Cache<String, T>> makeParentCache(boolean weakValuesInnerCache) {
        // The outer cache has weak keys, so that we do not leak class loaders, but strong values, because the
        // inner caches are only referenced by the outer cache internally.
        Caffeine<Object, Object> outerBuilder = Caffeine.newBuilder()
                .executor(cacheExecutor)
                .scheduler(Scheduler.systemScheduler())
                .recordStats()
                .weakKeys();
        // The inner cache has strong keys, since they are just strings, and expires entries 15 minutes after they are
        // added to the cache, so that classes defined by dynamically installed plugins become available even if there
        // were negative cache hits prior to the installation (ideally this would be done with a listener, in which case
        // this two-level Caffeine cache could possibly be replaced by something based on ClassValue, like
        // org.kohsuke.stapler.ClassLoaderValue). The values for the inner cache may be weak if needed; for example,
        // parentClassCache uses weak values to avoid leaking classes and their loaders.
        Caffeine<Object, Object> innerBuilder = Caffeine.newBuilder()
                .executor(cacheExecutor)
                .scheduler(Scheduler.systemScheduler())
                .recordStats()
                .expireAfterWrite(Duration.ofMinutes(15));
        if (weakValuesInnerCache) {
            innerBuilder.weakValues();
        }
        // In both cases above, note that by default Caffeine does not perform cleanup and evict values "automatically"
        // or instantly after a value expires. Instead, it performs small amounts of maintenance work after write
        // operations (or occasionally after read operations if writes are rare). When Caffeine is configured with its
        // default Executor of ForkJoinPool#commonPool, it immediately schedules an asynchronous eviction event after
        // such write operations; however, when using a custom executor, a scheduler is required in order to run the
        // maintenance activity in the near future rather than deferring it to a subsequent cache operation. Since
        // Caffeine does not define a default scheduler, we explicitly configure its scheduler to the recommended
        // dedicated system-wide Scheduler#systemScheduler. This preserves, as closely as possible, Caffeine's behavior
        // when using ForkJoinPool#commonPool. See
        // com.github.benmanes.caffeine.cache.BoundedLocalCache#rescheduleCleanUpIfIncomplete for details.

        return outerBuilder.build(parentLoader -> innerBuilder.build());
    }
}
