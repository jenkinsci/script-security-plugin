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

import com.google.common.io.NullOutputStream;
import groovy.lang.GString;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import org.codehaus.groovy.runtime.GStringImpl;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelistTest;
import static org.junit.Assert.*;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;

public class GroovyCallSiteSelectorTest {

    @Test public void arrays() throws Exception {
        Method m = EnumeratingWhitelistTest.C.class.getDeclaredMethod("m", Object[].class);
        assertEquals("literal call", m, GroovyCallSiteSelector.method(new EnumeratingWhitelistTest.C(), "m", new Object[] {new Object[] {"a", "b"}}));
        assertEquals("we assume the interceptor has dealt with varargs", null, GroovyCallSiteSelector.method(new EnumeratingWhitelistTest.C(), "m", new Object[] {"a", "b"}));
        assertEquals("array cast", m, GroovyCallSiteSelector.method(new EnumeratingWhitelistTest.C(), "m", new Object[] {new String[] {"a", "b"}}));
    }

    @Test public void overloads() throws Exception {
        PrintWriter receiver = new PrintWriter(new NullOutputStream());
        assertEquals(PrintWriter.class.getMethod("print", Object.class), GroovyCallSiteSelector.method(receiver, "print", new Object[] {new Object()}));
        assertEquals(PrintWriter.class.getMethod("print", String.class), GroovyCallSiteSelector.method(receiver, "print", new Object[] {"message"}));
        assertEquals(PrintWriter.class.getMethod("print", int.class), GroovyCallSiteSelector.method(receiver, "print", new Object[] {42}));
    }

    @Issue("JENKINS-29541")
    @Test public void methodsOnGString() throws Exception {
        GStringImpl gString = new GStringImpl(new Object[0], new String[] {"x"});
        assertEquals(String.class.getMethod("substring", int.class), GroovyCallSiteSelector.method(gString, "substring", new Object[] {99}));
        assertEquals(GString.class.getMethod("getValues"), GroovyCallSiteSelector.method(gString, "getValues", new Object[0]));
        assertEquals(GString.class.getMethod("getStrings"), GroovyCallSiteSelector.method(gString, "getStrings", new Object[0]));
    }

    @Issue("JENKINS-31701")
    @Test public void primitives() throws Exception {
        assertEquals(Primitives.class.getMethod("m1", long.class), GroovyCallSiteSelector.staticMethod(Primitives.class, "m1", new Object[] {Long.MAX_VALUE}));
        assertEquals(Primitives.class.getMethod("m1", long.class), GroovyCallSiteSelector.staticMethod(Primitives.class, "m1", new Object[] {99}));
        assertEquals(Primitives.class.getMethod("m2", long.class), GroovyCallSiteSelector.staticMethod(Primitives.class, "m2", new Object[] {Long.MAX_VALUE}));
        assertEquals(Primitives.class.getMethod("m2", int.class), GroovyCallSiteSelector.staticMethod(Primitives.class, "m2", new Object[] {99}));
    }
    public static class Primitives {
        public static void m1(long x) {}
        public static void m2(int x) {}
        public static void m2(long x) {}
    }

}
