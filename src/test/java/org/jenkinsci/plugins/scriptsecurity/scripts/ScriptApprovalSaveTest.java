/*
 * The MIT License
 *
 * Copyright 2026 CloudBees, Inc.
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

package org.jenkinsci.plugins.scriptsecurity.scripts;

import hudson.ExtensionList;
import hudson.XmlFile;
import hudson.model.Saveable;
import hudson.model.listeners.SaveableListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.concurrent.atomic.AtomicInteger;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Verifies that {@link ScriptApproval} avoids redundant saves when deserialization does not change state.
 */
@WithJenkins
class ScriptApprovalSaveTest {

    @TestExtension
    public static class ScriptApprovalSaveCounter extends SaveableListener {
        final AtomicInteger count = new AtomicInteger();

        @Override
        public void onChange(Saveable o, XmlFile file) {
            if (o instanceof ScriptApproval) {
                count.incrementAndGet();
            }
        }
    }

    /**
     * Verifies the {@code SecureGroovyScript.readResolve} → {@code configuring} →
     * {@code pendingScripts.add} flow.
     *
     * <p>Deserializing an unsandboxed {@link SecureGroovyScript} for the first time
     * should add the script to {@code pendingScripts} and save {@link ScriptApproval} once.
     * A second deserialization of the same bytes finds the pending entry already present,
     * so {@code pendingScripts.add} returns {@code false}, {@code changed} stays {@code false},
     * and {@code save()} is not called again.
     */
    @Test
    void readResolveDoesNotSaveIfAlreadyPending(JenkinsRule r) throws Exception {
        // Enable security so scripts are not auto-approved and end up in pendingScripts.
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());

        var sgs = new SecureGroovyScript("println 'hello'", false, null);
        byte[] serialized;
        try (var baos = new ByteArrayOutputStream();
             var oos = new ObjectOutputStream(baos)) {
            oos.writeObject(sgs);
            serialized = baos.toByteArray();
        }

        assertThat(ScriptApproval.get().getPendingScripts(), hasSize(0));
        var counter = ExtensionList.lookupSingleton(ScriptApprovalSaveCounter.class);

        // First deserialization: readResolve → configuring → pendingScripts.add returns true → save fires.
        try (var ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
            ois.readObject();
        }
        assertThat("first deserialization should save once", counter.count.get(), is(1));
        assertThat(ScriptApproval.get().getPendingScripts(), hasSize(1));

        // Second deserialization: same script already pending, pendingScripts.add returns false → no save.
        try (var ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
            ois.readObject();
        }
        assertThat("second deserialization should not save again", counter.count.get(), is(1));
        assertThat(ScriptApproval.get().getPendingScripts(), hasSize(1));
    }
}
