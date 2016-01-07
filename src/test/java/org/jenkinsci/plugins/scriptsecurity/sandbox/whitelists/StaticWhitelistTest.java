/*
 * The MIT License
 *
 * Copyright 2015 CloudBees, Inc.
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

import groovy.lang.GroovyObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;
import org.junit.Test;
import static org.junit.Assert.*;

public class StaticWhitelistTest {
    
    @Test public void dangerous() throws Exception {
        assertFalse(StaticWhitelist.rejectMethod(Collection.class.getMethod("clear")).isDangerous());
        assertTrue(StaticWhitelist.rejectNew(File.class.getConstructor(String.class)).isDangerous());
        assertTrue(StaticWhitelist.rejectMethod(GroovyObject.class.getMethod("invokeMethod", String.class, Object.class)).isDangerous());
    }

    static void sanity(URL definition) throws Exception {
        StaticWhitelist wl = StaticWhitelist.from(definition);
        List<EnumeratingWhitelist.Signature> sigs = new ArrayList<EnumeratingWhitelist.Signature>();
        InputStream is = definition.openStream();
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                sigs.add(StaticWhitelist.parse(line));
            }
        } finally {
            is.close();
        }
        assertEquals("entries in " + definition + " should be sorted and unique", new TreeSet<EnumeratingWhitelist.Signature>(sigs).toString(), sigs.toString());
        for (EnumeratingWhitelist.Signature sig : sigs) {
            assertTrue(sig + " exists", sig.exists());
        }
    }

    @Test public void sanity() throws Exception {
        sanity(StaticWhitelist.class.getResource("blacklist"));
    }

}
