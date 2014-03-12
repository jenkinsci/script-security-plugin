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

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import java.lang.reflect.Method;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelistTest;
import static org.junit.Assert.*;
import org.junit.Test;

public class GroovyCallSiteSelectorTest {

    @Test public void arrays() throws Exception {
        Method m = EnumeratingWhitelistTest.C.class.getDeclaredMethod("m", Object[].class);
        assertEquals("literal call", m, GroovyCallSiteSelector.method(new EnumeratingWhitelistTest.C(), "m", new Object[] {new Object[] {"a", "b"}}));
        assertEquals("we assume the interceptor has dealt with varargs", null, GroovyCallSiteSelector.method(new EnumeratingWhitelistTest.C(), "m", new Object[] {"a", "b"}));
        assertEquals("array cast", m, GroovyCallSiteSelector.method(new EnumeratingWhitelistTest.C(), "m", new Object[] {new String[] {"a", "b"}}));
    }

}
