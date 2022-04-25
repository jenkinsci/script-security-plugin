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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;

public class EnumeratingWhitelistTest {

    public static class C {
        public int myField = 5;

        public void m(Object[] args) {}
    }

    @Test public void matches() throws Exception {
        Method m = C.class.getMethod("m", Object[].class);
        assertTrue(new EnumeratingWhitelist.MethodSignature(C.class, "m", Object[].class).matches(m));
        assertTrue(new EnumeratingWhitelist.MethodSignature(C.class, "*", Object[].class).matches(m));
        assertFalse(new EnumeratingWhitelist.MethodSignature(C.class, "other", Object[].class).matches(m));
        assertFalse(new EnumeratingWhitelist.MethodSignature(C.class, "m", String[].class).matches(m));

        Field f = C.class.getField("myField");
        assertTrue(new EnumeratingWhitelist.FieldSignature(C.class, "*").matches(f));
        assertTrue(new EnumeratingWhitelist.FieldSignature(C.class, "myField").matches(f));
        assertFalse(new EnumeratingWhitelist.FieldSignature(C.class, "other").matches(f));
    }

    @Test public void getName() throws Exception {
        assertEquals("java.lang.Object", EnumeratingWhitelist.getName(Object.class));
        assertEquals("java.lang.Object[]", EnumeratingWhitelist.getName(Object[].class));
        assertEquals("java.lang.Object[][]", EnumeratingWhitelist.getName(Object[][].class));
        assertEquals(EnumeratingWhitelistTest.class.getName() + "$C", EnumeratingWhitelist.getName(C.class));
        for (Class<?> c : new Class<?>[] {String.class, Map.Entry.class, int.class, String[].class, Map.Entry[].class, int[].class, String[][].class, Map.Entry[][].class, int[][].class}) {
            assertEquals(c, EnumeratingWhitelist.Signature.type(EnumeratingWhitelist.getName(c)));
        }
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
        assertTrue(new EnumeratingWhitelist.MethodSignature(Map.Entry.class, "getKey").exists());
        assertTrue(new EnumeratingWhitelist.MethodSignature("java.util.Map$Entry", "getKey").exists());
        assertThrows(ClassNotFoundException.class, new EnumeratingWhitelist.MethodSignature("java.util.Map.Entry", "getKey")::exists);
    }

    @Test
    public void isWildcard() throws Exception {
        assertTrue(new EnumeratingWhitelist.MethodSignature(C.class, "*", Object[].class).isWildcard());
        assertFalse(new EnumeratingWhitelist.MethodSignature(C.class, "m", Object[].class).isWildcard());

        assertTrue(new EnumeratingWhitelist.FieldSignature(C.class, "*").isWildcard());
        assertFalse(new EnumeratingWhitelist.FieldSignature(C.class, "myField").isWildcard());
    }

    public static class Fancy {
        public static int myStaticF = 8;
        public int myF = 5;

        public void m(Object[] args) {}

        public static void staticM(Object arg){}

        public Fancy(){}
        public Fancy(int ob){}
    }

    /** Verifies for caching that canonical names match method signature toString, for cache keying. */
    @Test
    public void canonicalNaming() throws Exception {
        Method m = Fancy.class.getMethod("m", Object[].class);
        Method staticM = Fancy.class.getMethod("staticM", Object.class);
        Constructor<Fancy> con = Fancy.class.getConstructor(null);
        Field f = Fancy.class.getField("myF");
        Field staticF = Fancy.class.getField("myStaticF");

        EnumeratingWhitelist.MethodSignature mSig = new EnumeratingWhitelist.MethodSignature(Fancy.class, "m", Object[].class);
        String[] obString = {Object.class.getName()};
        EnumeratingWhitelist.StaticMethodSignature staticMSig = new EnumeratingWhitelist.StaticMethodSignature(Fancy.class.getName(), "staticM", obString);
        EnumeratingWhitelist.NewSignature conSig = new EnumeratingWhitelist.NewSignature(Fancy.class);
        EnumeratingWhitelist.FieldSignature fSig = new EnumeratingWhitelist.FieldSignature(Fancy.class, "myF");
        EnumeratingWhitelist.FieldSignature staticFSig = new EnumeratingWhitelist.StaticFieldSignature(Fancy.class.getName(), "myStaticF");

        Assert.assertEquals(mSig.toString(), EnumeratingWhitelist.canonicalMethodSig(m));
        Assert.assertEquals(staticMSig.toString(), EnumeratingWhitelist.canonicalStaticMethodSig(staticM));
        Assert.assertEquals(conSig.toString(), EnumeratingWhitelist.canonicalConstructorSig(con));
        Assert.assertEquals(fSig.toString(), EnumeratingWhitelist.canonicalFieldSig(f));
        Assert.assertEquals(staticFSig.toString(), EnumeratingWhitelist.canonicalStaticFieldSig(staticF));
    }

    @Test
    public void caching() throws Exception {
        StaticWhitelist myList = new StaticWhitelist();

        Method m = Fancy.class.getMethod("m", Object[].class);
        Method staticM = Fancy.class.getMethod("staticM", Object.class);
        Constructor<Fancy> con = Fancy.class.getConstructor(null);
        Field f = Fancy.class.getField("myF");
        Field staticF = Fancy.class.getField("myStaticF");

        EnumeratingWhitelist.MethodSignature mSig = new EnumeratingWhitelist.MethodSignature(Fancy.class, "m", Object[].class);
        String[] obString = {Object.class.getName()};
        EnumeratingWhitelist.StaticMethodSignature staticMSig = new EnumeratingWhitelist.StaticMethodSignature(Fancy.class.getName(), "staticM", obString);
        EnumeratingWhitelist.NewSignature conSig = new EnumeratingWhitelist.NewSignature(Fancy.class);
        EnumeratingWhitelist.FieldSignature fSig = new EnumeratingWhitelist.FieldSignature(Fancy.class, "myF");
        EnumeratingWhitelist.FieldSignature staticFSig = new EnumeratingWhitelist.StaticFieldSignature(Fancy.class.getName(), "myStaticF");

        // Each tested twice to allow for once with and once without caching
        // And we're checking cache entries and equality of canonical method name and signatures
        assertFalse(myList.permitsMethod(m, new Fancy(), null));
        assertFalse(myList.permitsMethod(m, new Fancy(), null));
        assertEquals(Boolean.FALSE, myList.permittedCache.get(mSig.toString()));

        assertFalse(myList.permitsStaticMethod(staticM, null));
        assertFalse(myList.permitsStaticMethod(staticM, null));
        assertEquals(Boolean.FALSE, myList.permittedCache.get(staticMSig.toString()));

        assertFalse(myList.permitsConstructor(con, null));
        assertFalse(myList.permitsConstructor(con, null));
        assertEquals(Boolean.FALSE, myList.permittedCache.get(conSig.toString()));

        assertFalse(myList.permitsFieldGet(f, new Fancy()));
        assertFalse(myList.permitsFieldGet(f, new Fancy()));
        assertEquals(Boolean.FALSE, myList.permittedCache.get(fSig.toString()));

        assertFalse(myList.permitsStaticFieldGet(staticF));
        assertFalse(myList.permitsStaticFieldGet(staticF));
        assertEquals(Boolean.FALSE, myList.permittedCache.get(staticFSig.toString()));

        // Now we clear, add matching signatures, and precache
        myList.clearCache();
        assertTrue(myList.permittedCache.isEmpty());
        myList.methodSignatures.add(mSig);
        myList.staticMethodSignatures.add(staticMSig);
        myList.newSignatures.add(conSig);
        myList.fieldSignatures.add(fSig);
        myList.staticFieldSignatures.add(staticFSig);
        myList.precache();

        // Just confirms we cached right
        assertEquals(Boolean.TRUE, myList.permittedCache.get(mSig.toString()));
        assertEquals(Boolean.TRUE, myList.permittedCache.get(staticMSig.toString()));
        assertEquals(Boolean.TRUE, myList.permittedCache.get(conSig.toString()));
        assertEquals(Boolean.TRUE, myList.permittedCache.get(fSig.toString()));
        assertEquals(Boolean.TRUE, myList.permittedCache.get(staticFSig.toString()));
    }

    @Test
    public void testCachingWithWildcards() throws Exception {
        StaticWhitelist myList = new StaticWhitelist();
        Field f = C.class.getField("myField");
        myList.fieldSignatures.add(new EnumeratingWhitelist.FieldSignature(C.class, "*"));

        myList.precache();
        assertTrue(myList.permittedCache.isEmpty());  // We cannot cache Wildcard matches directly, only when we see a method they permit

        assertTrue(myList.permitsFieldGet(f, new C()));  // No cache, so we fall back to direct search and hit the wildcard, then cache permitted
        assertTrue(myList.permitsFieldGet(f, new C()));  // Should hit cache for that specific method
        assertEquals(Boolean.TRUE, myList.permittedCache.get(EnumeratingWhitelist.canonicalFieldSig(f)));  // Verifies it can cache that
    }

}
