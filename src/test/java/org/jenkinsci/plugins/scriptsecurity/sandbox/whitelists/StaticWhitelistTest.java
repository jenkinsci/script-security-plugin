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
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.junit.Assert;
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
                line = StaticWhitelist.filter(line);
                if (line == null) {
                    continue;
                }
                sigs.add(StaticWhitelist.parse(line));
            }
        } finally {
            is.close();
        }

        HashSet<EnumeratingWhitelist.Signature> existingSigs = new HashSet<EnumeratingWhitelist.Signature>(sigs.size());
        boolean hasDupes = false;
        for (EnumeratingWhitelist.Signature sig : sigs) {
            if (!existingSigs.add(sig)) {
                System.out.println("Duplicate whitelist signature: "+sig);
                hasDupes = true;
            }
        }
        Assert.assertFalse("Whitelist contains duplicate entries, and this is not allowed!  Please see list above.", hasDupes);

        ArrayList<EnumeratingWhitelist.Signature> sorted = new ArrayList<EnumeratingWhitelist.Signature>(sigs);
        Collections.sort(sorted);

        boolean isUnsorted = false;
        for (int i=0; i<sigs.size(); i++) {
            EnumeratingWhitelist.Signature expectedSig = sorted.get(i);
            EnumeratingWhitelist.Signature actualSig = sigs.get(i);
            if (!expectedSig.equals(actualSig)) {
                System.out.println(MessageFormat.format("Signatures out of order, at index {0} found {1} but expected {2}", i, actualSig, expectedSig));
                isUnsorted = true;
            }
        }
        Assert.assertFalse("Whitelist is out of order!  Please see issues above.", isUnsorted);


        for (EnumeratingWhitelist.Signature sig : sigs) {
            try {
                assertTrue(sig + " does not exist (or is an override)", sig.exists());
            } catch (ClassNotFoundException x) {
                System.err.println("Cannot check validity of `" + sig + "` due to " + x);
            }
        }
    }

    @Test public void sanity() throws Exception {
        sanity(StaticWhitelist.class.getResource("blacklist"));
    }

}
