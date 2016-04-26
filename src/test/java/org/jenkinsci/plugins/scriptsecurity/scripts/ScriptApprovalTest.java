/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
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

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.JenkinsRule;
import com.gargoylesoftware.htmlunit.ConfirmHandler;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.Util;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicLong;

import org.jvnet.hudson.test.WithoutJenkins;

public class ScriptApprovalTest extends AbstractApprovalTest<ScriptApprovalTest.Script> {
    private static final String CLEAR_ALL_ID = "approvedScripts-clear";

    private static final AtomicLong COUNTER = new AtomicLong(0L);

    @Test public void emptyScript() throws Exception {
        configureSecurity();
        script("").use();
    }

    private Script script(String groovy) {
        return new Script(groovy);
    }

    @Override
    Script create() {
        return script("whatever" + COUNTER.incrementAndGet());
    }

    @Override
    void clearAllApproved() throws Exception {
        ScriptApproval.get().clearApprovedScripts();
    }

    @Override
    String getClearAllApprovedId() {
        return CLEAR_ALL_ID;
    }

    static final class Script extends Approvable<Script> {
        private final String groovy;
        private final String hash;

        Script(String groovy) {
            final ApprovalContext ac = ApprovalContext.create();
            this.groovy = ScriptApproval.get().configuring(groovy, GroovyLanguage.get(), ac);
            this.hash = new ScriptApproval.PendingScript(groovy, GroovyLanguage.get(), ac).getHash();
        }

        @Override
        boolean findPending() {
            for (ScriptApproval.PendingScript pending : ScriptApproval.get().getPendingScripts()) {
                if (pending.getHash().equals(hash)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        boolean findApproved() {
            return ScriptApproval.get().isScriptHashApproved(hash);
        }

        @Override
        Script use() {
            assertEquals(groovy, ScriptApproval.get().using(groovy, GroovyLanguage.get()));
            return this;
        }

        @Override
        boolean canUse() throws Exception {
            try {
                use();
            } catch(UnapprovedUsageException e) {
                return false;
            }
            return true;
        }

        @Override
        Script approve() throws IOException {
            final ScriptApproval sa = ScriptApproval.get();
            for (ScriptApproval.PendingScript pending : sa.getPendingScripts()) {
                if (pending.script.equals(groovy)) {
                    sa.approveScript(pending.getHash());
                    return this;
                }
            }
            fail(this + " was not pending approval");
            return this;
        }

        @Override
        Script deny() throws IOException {
            assertPending();
            ScriptApproval.get().denyScript(hash);
            return this;
        }

        private String ps() {
            return "ps-" + hash;
        }

        @Override
        Manager.Element<Script> pending(Manager manager) {
            assertPending();
            return manager.found(this, ps());
        }

        @Override
        Manager.Element<Script> approved(Manager manager) {
            assertApproved();
            // No further action for approved, return the section element.
            return manager.notFound(this, ps()).found(this, CLEAR_ALL_ID);
        }

        @Override
        Script assertDeleted(Manager manager) {
            assertDeleted();
            manager.notFound(this, ps());
            return this;
        }

        @Override
        public String toString() {
            return String.format("Script[%s]", groovy);
        }
    }

}
