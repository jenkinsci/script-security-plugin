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
import java.io.StringReader;
import java.util.Collections;

import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;

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

}
