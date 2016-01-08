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

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;

public class EnumeratingWhitelistTest {

    public static class C {
        public void m(Object[] args) {}
    }

    @Test public void matches() throws Exception {
        Method m = C.class.getMethod("m", Object[].class);
        assertTrue(new EnumeratingWhitelist.MethodSignature(C.class, "m", Object[].class).matches(m));
        assertTrue(new EnumeratingWhitelist.MethodSignature(C.class, "*", Object[].class).matches(m));
        assertFalse(new EnumeratingWhitelist.MethodSignature(C.class, "other", Object[].class).matches(m));
        assertFalse(new EnumeratingWhitelist.MethodSignature(C.class, "m", String[].class).matches(m));
    }

    @Test public void getName() {
        assertEquals("java.lang.Object", EnumeratingWhitelist.getName(Object.class));
        assertEquals("java.lang.Object[]", EnumeratingWhitelist.getName(Object[].class));
        assertEquals("java.lang.Object[][]", EnumeratingWhitelist.getName(Object[][].class));
        assertEquals(EnumeratingWhitelistTest.class.getName() + "$C", EnumeratingWhitelist.getName(C.class));
    }

    @Test public void methodExists() throws Exception {
        assertTrue(new EnumeratingWhitelist.MethodSignature(Object.class, "equals", Object.class).exists());
        assertFalse(new EnumeratingWhitelist.MethodSignature(String.class, "equals", Object.class).exists());
        assertFalse(new EnumeratingWhitelist.MethodSignature(String.class, "compareTo", Object.class).exists());
        /* TODO bridge methods should be considered to not exist, but this does not yet work:
        assertFalse(new EnumeratingWhitelist.MethodSignature(String.class, "compareTo", String.class).exists());
        */
        assertTrue(new EnumeratingWhitelist.MethodSignature(String.class, "compareToIgnoreCase", String.class).exists());
        assertFalse(new EnumeratingWhitelist.MethodSignature(LinkedHashMap.class, "size").exists());
        assertFalse(new EnumeratingWhitelist.MethodSignature(HashMap.class, "size").exists());
        assertTrue(new EnumeratingWhitelist.MethodSignature(Map.class, "size").exists());
    }

}
