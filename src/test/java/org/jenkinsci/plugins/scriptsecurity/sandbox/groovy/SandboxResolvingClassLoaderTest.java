/*
 * The MIT License
 *
 * Copyright 2019 CloudBees, Inc.
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

import com.github.benmanes.caffeine.cache.stats.CacheStats;
import java.lang.management.LockInfo;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.CountDownLatch;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxResolvingClassLoader.CLASS_NOT_FOUND;
import static org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxResolvingClassLoader.parentClassCache;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class SandboxResolvingClassLoaderTest {

    @Issue("JENKINS-59587")
    @Test public void classCacheDoesNotHoldClassValuesTooWeakly() throws Exception {
        ClassLoader parentLoader = SandboxResolvingClassLoaderTest.class.getClassLoader();
        SandboxResolvingClassLoader loader = new SandboxResolvingClassLoader(parentLoader);
        // Load a class that does exist.
        assertThat(loader.loadClass("java.lang.String"), equalTo(String.class));
        // Load a class that does not exist.
        try {
            loader.loadClass("this.does.not.Exist");
            fail("Class should not exist");
        } catch (ClassNotFoundException e) {
            assertThat(e.getMessage(), containsString("this.does.not.Exist"));
        }
        // The result of both of the class loading attempts should exist in the cache.
        assertThat(loadClass(parentLoader, "java.lang.String"), equalTo(String.class));
        assertThat(loadClass(parentLoader, "this.does.not.Exist"), equalTo(CLASS_NOT_FOUND));
        // Make sure that both of the entries are still in the cache after a GC.
        System.gc();
        assertThat(loadClass(parentLoader, "java.lang.String"), equalTo(String.class));
        assertThat(loadClass(parentLoader, "this.does.not.Exist"), equalTo(CLASS_NOT_FOUND));
        CacheStats stats = parentClassCache.get(parentLoader).synchronous().stats();
        // Before the fix for JENKINS-59587, the original inner cache was removed after the call to `System.gc()`, so
        // the miss count was 2 and the hit count was 0.
        assertThat(stats.missCount(), equalTo(2L)); // The two calls to `loadClass()`
        assertThat(stats.hitCount(), equalTo(4L)); // The four calls to `getIfPresent()`
    }

    @Test public void classCacheOnlyBlocksAtLoadClass() throws Exception {
        ControlledBlockingClassLoader parentLoader = new ControlledBlockingClassLoader(SandboxResolvingClassLoaderTest.class.getClassLoader());
        // Load a bunch of classes using the same blocking parent class loader so they share an inner cache. While we
        // expect to see all of the threads blocked inside of `ControlledBlockingClassLoader.loadClass` on the latch,
        // before the fix for JENKINS-XXX, some threads end up blocked earlier on a call to `ConcurrentHashMap.compute`
        // on the map backing the cache, waiting to lock a `ConcurrentHashMap$ReservationNode` locked by one of the other
        // threads blocked in `ControlledBlockingClassLoader.loadClass`. The default cache size is 16, so we load 16 + 32
        // values so that we fill the initial table to capacity, and then fill the resized table, to make it more likely
        // to trigger the bug.
        for (int i = 0; i < 16 + 32; i++) {
            final int j = i;
            SandboxResolvingClassLoader loader = new SandboxResolvingClassLoader(parentLoader);
            runInNewThread("blocker-" + j, () -> loader.loadClass("com.foo.Bar"+j));
        }
        Thread.sleep(500); // Try to wait for all of the futures to be inserted into the map.
        ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        long[] threadIds = threadBean.getAllThreadIds();
        for (long threadId : threadIds) {
            ThreadInfo threadInfo = threadBean.getThreadInfo(threadId, 16);
            if (threadInfo != null && threadInfo.getThreadName().startsWith("blocker-")) {
                LockInfo lockInfo = threadInfo.getLockInfo();
                if (lockInfo != null) {
                    assertThat(threadInfo.getThreadName(), containsString("loading com.foo.Bar"));
                    assertThat(threadInfo.getLockInfo().getClassName(), not(equalTo("java.util.concurrent.ConcurrentHashMap$ReservationNode")));
                }
            }
        }
        parentLoader.latch.countDown();
    }

    private static Class<?> loadClass(ClassLoader loader, String className) throws Exception {
        return parentClassCache.get(loader).getIfPresent(className).get().get();
    }

    private static void runInNewThread(String name, ThrowingRunnable r) {
        Thread thread = new Thread(() -> {
            try {
                r.run();
            } catch (ClassNotFoundException e) {
                // Ignore
            } catch (Throwable e) {
                throw new AssertionError(e);
            }
        }, name);
        thread.start();
    }

    @FunctionalInterface
    private static interface ThrowingRunnable {
        public void run() throws Throwable;
    }

    private static class ControlledBlockingClassLoader extends ClassLoader {
        private volatile CountDownLatch latch = new CountDownLatch(1);
        public ControlledBlockingClassLoader(ClassLoader parent) {
            super(parent);
        }
        @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            try {
                latch.await();
                return getParent().loadClass(name);
            } catch (InterruptedException e) {
                throw new AssertionError(e);
            }
        }
    }
}
