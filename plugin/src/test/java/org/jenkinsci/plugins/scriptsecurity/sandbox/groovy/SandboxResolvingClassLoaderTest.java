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
import org.junit.Test;
import org.jvnet.hudson.test.Issue;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxResolvingClassLoader.CLASS_NOT_FOUND;
import static org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxResolvingClassLoader.parentClassCache;
import static org.junit.Assert.assertThrows;

public class SandboxResolvingClassLoaderTest {

    private final ClassLoader parentLoader = SandboxResolvingClassLoaderTest.class.getClassLoader();
    private final SandboxResolvingClassLoader loader = new SandboxResolvingClassLoader(parentLoader);

    @Issue("JENKINS-59587")
    @Test public void classCacheDoesNotHoldClassValuesTooWeakly() throws Exception {
        // Load a class that does exist.
        assertThat(loader.loadClass("java.lang.String", false), equalTo(String.class));
        // Load a class that does not exist.
        final ClassNotFoundException e = assertThrows(ClassNotFoundException.class,
                () -> loader.loadClass("this.does.not.Exist", false));
        assertThat(e.getMessage(), containsString("this.does.not.Exist"));
        // The result of both of the class loading attempts should exist in the cache.
        assertThat(parentClassCache.get(parentLoader).getIfPresent("java.lang.String"), equalTo(String.class));
        assertThat(parentClassCache.get(parentLoader).getIfPresent("this.does.not.Exist"), equalTo(CLASS_NOT_FOUND));
        // Make sure that both of the entries are still in the cache after a GC.
        System.gc();
        assertThat(parentClassCache.get(parentLoader).getIfPresent("java.lang.String"), equalTo(String.class));
        assertThat(parentClassCache.get(parentLoader).getIfPresent("this.does.not.Exist"), equalTo(CLASS_NOT_FOUND));
        CacheStats stats = parentClassCache.get(parentLoader).stats();
        // Before the fix for JENKINS-59587, the original inner cache was removed after the call to `System.gc()`, so
        // the miss count was 2 and the hit count was 0.
        assertThat(stats.missCount(), equalTo(2L)); // The two calls to `loadClass()`
        assertThat(stats.hitCount(), equalTo(4L)); // The four calls to `getIfPresent()`
    }
}
