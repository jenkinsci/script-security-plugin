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
import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import org.junit.Test;
import static org.junit.Assert.*;

public class ProxyWhitelistTest {

    @Test public void reset() throws IOException {
        ProxyWhitelist pw1 = new ProxyWhitelist(new StaticWhitelist(new StringReader("method java.lang.String length")));
        ProxyWhitelist pw2 = new ProxyWhitelist(pw1);
        assertTrue(pw2.permitsMethod("x", "length", new Object[0]));
        assertFalse(pw2.permitsMethod("x", "hashCode", new Object[0]));
        pw1.reset(Collections.singleton(new StaticWhitelist(new StringReader("method java.lang.String length\nmethod java.lang.String hashCode"))));
        assertTrue(pw2.permitsMethod("x", "length", new Object[0]));
        assertTrue(pw2.permitsMethod("x", "hashCode", new Object[0]));
        pw1.reset(Collections.<Whitelist>emptySet());
        assertFalse(pw2.permitsMethod("x", "length", new Object[0]));
        assertFalse(pw2.permitsMethod("x", "hashCode", new Object[0]));
    }

}
