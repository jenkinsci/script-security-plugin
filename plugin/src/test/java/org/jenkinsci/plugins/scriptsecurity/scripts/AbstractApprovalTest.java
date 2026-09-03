/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick, CloudBees Inc.
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

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public abstract class AbstractApprovalTest<T extends Approvable<T>> {

    @Rule public JenkinsRule r = new JenkinsRule();

    /** Creates a new approvable to test. */
    abstract T create() throws Exception;

    @Test public void noSecurity() throws Exception {
        create().use();
    }

    @Test public void withSecurity() throws Exception {
        configureSecurity();
        // Cannot use until approved
        create().assertCannotUse().approve().use();
    }

    void configureSecurity() {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
    }

    abstract void clearAllApproved() throws Exception;

    /** Returns the id of the section containing the clear all button. */
    String getClearAllApprovedId() {
        return null;
    }

    private Approvable<?>[] createFiveEntries() throws Exception {
        final Approvable<?>[] entries = new Approvable<?>[5];
        for (int i = 0; i < entries.length; i++) {
            entries[i] = create().assertPending();
        }
        return entries;
    }

    @Test public void approveInternal() throws Exception {
        configureSecurity();
        final Approvable<?>[] entries = createFiveEntries();
        entries[0].approve().assertApproved();
        entries[1].approve().assertApproved();
        entries[2].deny().assertDeleted();
        entries[3].approve().assertApproved();
        if (entries[3].canDelete()) {
            entries[3].delete().assertDeleted();
        }
        clearAllApproved();
        for (int i = 0; i < 4; i++) {
            entries[i].assertDeleted();
        }
        entries[4].assertPending();
    }


    @Test public void approveExternal() throws Exception {
        configureSecurity();
        final Approvable<?>[] entries = createFiveEntries();

        final Manager manager = new Manager(r);

        for (Approvable<?> entry : entries) {
            entry.pending(manager);
        }

        entries[0].pending(manager).approve().approved(manager);
        entries[1].pending(manager).approve().approved(manager);
        entries[2].pending(manager).deny().assertDeleted();
        entries[3].pending(manager).approve().approved(manager);
        if (entries[3].canDelete()) {
            entries[3].approved(manager).delete().assertDeleted(manager);
        }

        // clear all classpaths
        final String clearId = getClearAllApprovedId();
        if (clearId != null) {
            manager.click(clearId);
            for (int i = 0; i < 4; i++) {
                entries[i].assertDeleted(manager);
            }
        }
        // The last one remains pending
        entries[4].pending(manager);
    }
}
