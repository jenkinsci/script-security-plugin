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
import java.util.Random;
import java.util.Set;

import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelist.MethodSignature;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelist.Signature;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.EnumeratingWhitelist.StaticMethodSignature;
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
        List<EnumeratingWhitelist.Signature> sigs = new ArrayList<>();
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

        HashSet<EnumeratingWhitelist.Signature> existingSigs = new HashSet<>(sigs.size());
        boolean hasDupes = false;
        for (EnumeratingWhitelist.Signature sig : sigs) {
            if (!existingSigs.add(sig)) {
                System.out.println("Duplicate whitelist signature: "+sig);
                hasDupes = true;
            }
        }
        Assert.assertFalse("Whitelist contains duplicate entries, and this is not allowed!  Please see list above.", hasDupes);

        ArrayList<EnumeratingWhitelist.Signature> sorted = new ArrayList<>(sigs);
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
            if (KNOWN_GOOD_SIGNATURES.contains(sig)) {
                continue;
            }
            try {
                assertTrue(sig + " does not exist (or is an override)", sig.exists());
            } catch (ClassNotFoundException x) {
                // Wrapping exception to include the full signature in the error message.
                throw new Exception("Unable to verify existence of " + sig, x);
            }
        }
    }

    /**
     * A set of signatures that are well-formed, but for which {@link Signature#exists} may throw an exception depending
     * on the test environment.
     */
    private static final Set<Signature> KNOWN_GOOD_SIGNATURES = new HashSet<>(Arrays.asList(
            // From workflow-support, which is not a dependency of this plugin.
            new MethodSignature("org.jenkinsci.plugins.workflow.support.steps.build.RunWrapper", "getRawBuild"),
            // From groovy-cps, which is not a dependency of this plugin.
            new StaticMethodSignature("com.cloudbees.groovy.cps.CpsDefaultGroovyMethods", "each",
                    "java.util.Iterator", "groovy.lang.Closure"),
            // Overrides CharSequence.isEmpty in Java 15+.
            new MethodSignature(String.class, "isEmpty"),
            // Does not exist until Java 15.
            new MethodSignature(CharSequence.class, "isEmpty"),
            // Override the corresponding RandomGenerator methods in Java 17+.
            new MethodSignature(Random.class, "nextBoolean"),
            new MethodSignature(Random.class, "nextBytes", byte[].class),
            new MethodSignature(Random.class, "nextDouble"),
            new MethodSignature(Random.class, "nextFloat"),
            new MethodSignature(Random.class, "nextGaussian"),
            new MethodSignature(Random.class, "nextInt"),
            new MethodSignature(Random.class, "nextInt", int.class),
            new MethodSignature(Random.class, "nextLong"),
            // Do not exist until Java 17.
            new MethodSignature("java.util.random.RandomGenerator", "nextBoolean"),
            new MethodSignature("java.util.random.RandomGenerator", "nextBytes", "byte[]"),
            new MethodSignature("java.util.random.RandomGenerator", "nextDouble"),
            new MethodSignature("java.util.random.RandomGenerator", "nextFloat"),
            new MethodSignature("java.util.random.RandomGenerator", "nextGaussian"),
            new MethodSignature("java.util.random.RandomGenerator", "nextInt"),
            new MethodSignature("java.util.random.RandomGenerator", "nextInt", "int"),
            new MethodSignature("java.util.random.RandomGenerator", "nextLong")
    ));

    @Test public void sanity() throws Exception {
        sanity(StaticWhitelist.class.getResource("blacklist"));
    }

}
