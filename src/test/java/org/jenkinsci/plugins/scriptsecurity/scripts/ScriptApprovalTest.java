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

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.util.VersionNumber;
import jenkins.model.Jenkins;
import org.hamcrest.Matchers;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.TestGroovyRecorder;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.recipes.LocalData;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;

import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ScriptApprovalTest extends AbstractApprovalTest<ScriptApprovalTest.Script> {
    @Rule
    public LoggerRule logging = new LoggerRule();

    private static final String CLEAR_ALL_ID = "approvedScripts-clear";

    private static final AtomicLong COUNTER = new AtomicLong(0L);

    private static final String WHITELISTED_SIGNATURE = "method java.lang.String trim";
    private static final String DANGEROUS_SIGNATURE = "staticMethod hudson.model.User current";

    @Test public void emptyScript() throws Exception {
        configureSecurity();
        script("").use();
    }

    @Issue("JENKINS-46764")
    @Test
    @LocalData("malformedScriptApproval")
    public void malformedScriptApproval() throws Exception {
        logging.record(ScriptApproval.class, Level.FINER).capture(100);
        try {
            Whitelist w = new ScriptApproval.ApprovedWhitelist();
        } catch (Exception e) {
            // ignore - we want to make sure we're logging this properly.
        }
        assertThat(logging.getRecords(), Matchers.hasSize(Matchers.equalTo(1)));
        assertEquals("Malformed signature entry in scriptApproval.xml: ' new java.lang.Exception java.lang.String'",
                logging.getRecords().get(0).getMessage());
    }

    @Test @LocalData("dangerousApproved") public void dangerousApprovedSignatures() {
        String[] dangerousSignatures = ScriptApproval.get().getDangerousApprovedSignatures();
        assertEquals(1, dangerousSignatures.length);
    }

    @Test @LocalData("dangerousApproved") public void dangerousApprovedWarnings() throws IOException, SAXException {
        JenkinsRule.WebClient wc = r.createWebClient();
        HtmlPage managePage = wc.goTo("manage");

        List<?> scriptApprovalLinks = managePage.getByXPath("//a[@href='scriptApproval']");
        int expectedLinkCount = 2;
        if (Jenkins.getVersion().isNewerThan(new VersionNumber("2.102"))) {
            expectedLinkCount = 1; // https://github.com/jenkinsci/jenkins/pull/2857 made major changes to management page
        }
        assertEquals(expectedLinkCount, scriptApprovalLinks.size()); // the icon link and the textual link

        String managePageBodyText = managePage.getBody().getTextContent();
        assertThat(managePageBodyText, Matchers.containsString("1 dangerous signatures previously approved which ought not have been."));

        HtmlPage scriptApprovalPage = managePage.getAnchorByHref("scriptApproval").click();
        HtmlTextArea approvedTextArea = scriptApprovalPage.getHtmlElementById("approvedSignatures");
        HtmlTextArea dangerousTextArea = scriptApprovalPage.getHtmlElementById("dangerousApprovedSignatures");

        assertThat(approvedTextArea.getTextContent(), Matchers.containsString(DANGEROUS_SIGNATURE));
        assertThat(dangerousTextArea.getTextContent(), Matchers.containsString(DANGEROUS_SIGNATURE));
    }

    @Test public void nothingHappening() throws Exception {
        assertThat(r.createWebClient().goTo("manage").getByXPath("//a[@href='scriptApproval']"), Matchers.empty());
    }

    @Issue("SECURITY-1866")
    @Test public void classpathEntriesEscaped() throws Exception {
        // Add pending classpath entry.
        String hash = null;
        try {
            ScriptApproval.get().using(new ClasspathEntry("https://www.example.com/#value=Hack<img id='xss' src=x onerror=alert(123)>Hack"));
            fail("Classpath should not already be approved");
        } catch (UnapprovedClasspathException e) {
            hash = e.getHash();
        }
        // Check for XSS in pending approvals.
        JenkinsRule.WebClient wc = r.createWebClient();
        HtmlPage approvalPage = wc.goTo("scriptApproval");
        assertThat(approvalPage.getElementById("xss"), nullValue());
        // Approve classpath entry.
        ScriptApproval.get().approveClasspathEntry(hash);
        // Check for XSS in approved classpath entries.
        HtmlPage approvedPage = wc.goTo("scriptApproval");
        assertThat(approvedPage.getElementById("xss"), nullValue());
    }

    @Test public void clearMethodsLifeCycle() throws Exception {
        ScriptApproval sa = ScriptApproval.get();
        assertEquals(0, sa.getApprovedSignatures().length);

        sa.approveSignature(WHITELISTED_SIGNATURE);
        assertEquals(1, sa.getApprovedSignatures().length);
        assertEquals(0, sa.getDangerousApprovedSignatures().length);

        sa.approveSignature(DANGEROUS_SIGNATURE);
        assertEquals(2, sa.getApprovedSignatures().length);
        assertEquals(1, sa.getDangerousApprovedSignatures().length);

        sa.clearApprovedSignatures();
        assertEquals(0, sa.getApprovedSignatures().length);
        assertEquals(0, sa.getDangerousApprovedSignatures().length);

        sa.approveSignature(WHITELISTED_SIGNATURE);
        sa.approveSignature(DANGEROUS_SIGNATURE);
        assertEquals(2, sa.getApprovedSignatures().length);
        assertEquals(1, sa.getDangerousApprovedSignatures().length);

        sa.clearDangerousApprovedSignatures();
        assertEquals(1, sa.getApprovedSignatures().length);
        assertEquals(0, sa.getDangerousApprovedSignatures().length);
    }

    @Issue({"JENKINS-57563", "JENKINS-62708"})
    @LocalData // Just a scriptApproval.xml that whitelists 'staticMethod jenkins.model.Jenkins getInstance' and a script printing all labels
    @Test
    public void upgradeSmokes() throws Exception {
        configureSecurity();
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(
                new SecureGroovyScript("jenkins.model.Jenkins.instance", true, null)));
        p.getPublishersList().add(new TestGroovyRecorder(
                new SecureGroovyScript("println(jenkins.model.Jenkins.instance.getLabels())", false, null)));
        r.assertLogNotContains("org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException: script not yet approved for use",
                r.assertBuildStatus(Result.SUCCESS, p.scheduleBuild2(0).get()));
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
