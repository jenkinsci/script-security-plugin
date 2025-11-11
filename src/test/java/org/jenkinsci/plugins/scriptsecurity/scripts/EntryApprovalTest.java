/*
 * The MIT License
 *
 * Copyright 2016 CloudBees, Inc.
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

import hudson.Util;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.jvnet.hudson.test.WithoutJenkins;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EntryApprovalTest extends AbstractApprovalTest<EntryApprovalTest.Entry> {

    @TempDir
    private File tmp;

    private final SecureRandom random = new SecureRandom();

    @Override
    Entry create() throws Exception {
        final File file = File.createTempFile("junit", null, tmp);
        final byte[] bytes = new byte[1024];
        random.nextBytes(bytes);
        FileUtils.writeByteArrayToFile(file, bytes);
        return entry(file);
    }

    @Override
    void clearAllApproved() throws Exception {
        ScriptApproval.get().clearApprovedClasspathEntries();
    }

    @Override
    String getClearAllApprovedId() {
        return "approvedClasspathEntries-clear";
    }


    @Test
    void classDirRejectedEvenWithNoSecurity() throws Exception {
        entry(newFolder(tmp, "junit"));
        assertTrue(ScriptApproval.get().getPendingClasspathEntries().isEmpty(), "Class directory shouldn't be pending");
        assertTrue(ScriptApproval.get().getApprovedClasspathEntries().isEmpty(), "Class directory shouldn't be accepted");
    }

    // http://stackoverflow.com/a/25393190/12916
    @WithoutJenkins
    @Test
    void getPendingClasspathEntry() throws Exception {
        TreeSet<ScriptApproval.PendingClasspathEntry> pendingClasspathEntries = new TreeSet<>();
        for (int i = 1; i < 100; i++) {
            pendingClasspathEntries.add(new ScriptApproval.PendingClasspathEntry(hashOf(i), new URL("file:/x" + i + ".jar"), ApprovalContext.create()));
        }
        ScriptApproval.PendingClasspathEntry dummy = new ScriptApproval.PendingClasspathEntry(hashOf(77), null, null);
        ScriptApproval.PendingClasspathEntry real = pendingClasspathEntries.floor(dummy);
        assertEquals(real, dummy);
        assertEquals("file:/x77.jar", real.getURL().toString());
    }

    private static String hashOf(int i) {
        return Util.getDigestOf("hash #" + i);
    }

    private static Entry entry(File f) throws Exception {
        return new Entry(new ClasspathEntry(f.toURI().toURL().toExternalForm()));
    }

    static final class Entry extends Approvable<Entry> {
        private final ClasspathEntry entry;
        private final String hash;

        Entry(ClasspathEntry entry) throws IOException {
            this.entry = entry;
            ScriptApproval.get().configuring(entry, ApprovalContext.create());
            // If configure is successful, calculate the hash
            this.hash = ScriptApproval.DEFAULT_HASHER.hashClasspathEntry(entry.getURL());
        }

        @Override
        Entry use() throws IOException {
            ScriptApproval.get().using(entry);
            return this;
        }

        @Override
        boolean canUse() throws Exception {
            try {
                use();
            } catch(UnapprovedClasspathException e) {
                return false;
            }
            return true;
        }

        @Override
        boolean findPending() {
            for (ScriptApproval.PendingClasspathEntry pending : ScriptApproval.get().getPendingClasspathEntries()) {
                if (pending.getHash().equals(hash)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        boolean findApproved() {
            for (ScriptApproval.ApprovedClasspathEntry approved : ScriptApproval.get().getApprovedClasspathEntries()) {
                if (approved.getHash().equals(hash)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        Entry approve() throws IOException {
            assertPending();
            ScriptApproval.get().approveClasspathEntry(hash);
            return this;
        }

        @Override
        Entry deny() throws IOException {
            assertPending();
            ScriptApproval.get().denyClasspathEntry(hash);
            return this;
        }

        @Override
        boolean canDelete() {
            return true;
        }

        @Override
        Entry delete() throws IOException {
            assertApproved();
            ScriptApproval.get().denyApprovedClasspathEntry(hash);
            return this;
        }

        private String acp() {
            return "acp-" + hash;
        }

        private String pcp() {
            return "pcp-" + hash;
        }

        @Override
        Manager.Element<Entry> pending(Manager manager) {
            assertPending();
            return manager.notFound(this, acp()).found(this, pcp());
        }

        @Override
        Manager.Element<Entry> approved(Manager manager) {
            assertApproved();
            return manager.notFound(this, pcp()).found(this, acp());
        }

        @Override
        Entry assertDeleted(Manager manager) {
            assertDeleted();
            manager.notFound(this, pcp()).notFound(this, acp());
            return this;
        }

        @Override
        public String toString() {
            return String.format("ClasspathEntry[%s]", entry.getURL());
        }
    }

    private static File newFolder(File root, String... subDirs) throws IOException {
        String subFolder = String.join("/", subDirs);
        File result = new File(root, subFolder);
        if (!result.mkdirs()) {
            throw new IOException("Couldn't create folders " + root);
        }
        return result;
    }
}
