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

package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;

import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProxyWhitelistTest {

    @Test public void reset() throws Exception {
        ProxyWhitelist pw1 = new ProxyWhitelist(new StaticWhitelist(new StringReader("method java.lang.String length")));
        ProxyWhitelist pw2 = new ProxyWhitelist(pw1);
        assertTrue(pw2.permitsMethod(String.class.getMethod("length"), "x", new Object[0]));
        assertFalse(pw2.permitsMethod(Object.class.getMethod("hashCode"), "x", new Object[0]));
        pw1.reset(Collections.singleton(new StaticWhitelist(new StringReader("method java.lang.String length\nmethod java.lang.Object hashCode"))));
        assertTrue(pw2.permitsMethod(String.class.getMethod("length"), "x", new Object[0]));
        assertTrue(pw2.permitsMethod(Object.class.getMethod("hashCode"), "x", new Object[0]));
        pw1.reset(Collections.<Whitelist>emptySet());
        assertFalse(pw2.permitsMethod(String.class.getMethod("length"), "x", new Object[0]));
        assertFalse(pw2.permitsMethod(Object.class.getMethod("hashCode"), "x", new Object[0]));
    }

    @Test public void resetStaticField() throws Exception {
        ProxyWhitelist pw1 = new ProxyWhitelist(new StaticWhitelist(new StringReader("staticField java.util.Collections EMPTY_LIST")));
        ProxyWhitelist pw2 = new ProxyWhitelist(pw1);
        assertTrue(pw2.permitsStaticFieldGet(Collections.class.getField("EMPTY_LIST")));
        pw1.reset(Collections.<Whitelist>emptySet());
        assertFalse(pw2.permitsStaticFieldGet(Collections.class.getField("EMPTY_LIST")));
    }

    /** Ensures we cache at the top-level ProxyWhitelist */
    @Test
    public void caching() throws Exception {
        ProxyWhitelist pw1 = new ProxyWhitelist(new StaticWhitelist(new StringReader("method java.lang.String length")));
        assertEquals(1, ((EnumeratingWhitelist)pw1.delegates.get(0)).permittedCache.size());

        ProxyWhitelist pw2 = new ProxyWhitelist(pw1, new StaticWhitelist(new StringReader("method java.lang.String trim")));
        assertEquals(0, ((EnumeratingWhitelist)pw1.delegates.get(0)).permittedCache.size());
        assertEquals(2, ((EnumeratingWhitelist)pw2.delegates.get(0)).permittedCache.size());
    }

    /**
     * Test concurrent modification of delegates when initializing a ProxyWhitelist. This may cause concurrent threads 
     * to enter an infinite loop when using a {@link java.util.WeakHashMap} to hold the delegates as it is not 
     * synchronized. This is a rare case that is also related to Garbage Collection.
     * If contention is acceptable and/or the delegates collection behave, this test should be quite fast, just a few 
     * seconds. A timeout is allowed to process the creation of 1000000 {@link ProxyWhitelist} using an original 
     * delegate. If the tasks have not completed by then, we can assume that there is a problem.
     */
    @Issue("JENKINS-41797")
    @Test(timeout = 30000)
    public void testConcurrent() throws InterruptedException, IOException {
        int threadPoolSize = 2;
        ProxyWhitelist pw1 = new ProxyWhitelist(new StaticWhitelist(new StringReader("staticField java.util.Collections EMPTY_LIST")));

        ExecutorService es = Executors.newFixedThreadPool(threadPoolSize);
        
        for (int i = 1; i < 1000000; i++) {
            es.submit(() -> {
                new ProxyWhitelist(pw1);
            });
        }

        es.shutdown();
        // If interrupted after the timeout, something went wrong
        assert es.awaitTermination(10000, TimeUnit.MILLISECONDS);
    }

}
