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

import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlTextArea;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Result;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.Permission;
import hudson.util.VersionNumber;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.hamcrest.Matchers;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.TestGroovyRecorder;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.recipes.LocalData;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItemInArray;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ScriptApprovalTest extends AbstractApprovalTest<ScriptApprovalTest.Script> {
    @Rule
    public LoggerRule logging = new LoggerRule().record(ScriptApproval.class, Level.FINER).capture(100);

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
        assertThat(Whitelist.all().permitsMethod(Jenkins.class.getMethod("get"), null, null), is(false));
        assertThat(logging.getRecords().stream().map(r -> r.getMessage()).toArray(String[]::new),
            hasItemInArray("Malformed signature entry in scriptApproval.xml: ' new java.lang.Exception java.lang.String'"));
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
        final UnapprovedClasspathException e = assertThrows(UnapprovedClasspathException.class, () ->
            ScriptApproval.get().using(new ClasspathEntry("https://www.example.com/#value=Hack<img id='xss' src=x onerror=alert(123)>Hack")));

        // Check for XSS in pending approvals.
        JenkinsRule.WebClient wc = r.createWebClient();
        HtmlPage approvalPage = wc.goTo("scriptApproval");
        assertThat(approvalPage.getElementById("xss"), nullValue());
        // Approve classpath entry.
        ScriptApproval.get().approveClasspathEntry(e.getHash());
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
        r.assertLogNotContains("org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException: "
                        + "Scripts not permitted to use staticMethod jenkins.model.Jenkins getInstance",
                r.assertBuildStatus(Result.SUCCESS, p.scheduleBuild2(0).get()));
        r.assertLogNotContains("org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException: script not yet approved for use",
                r.assertBuildStatus(Result.SUCCESS, p.scheduleBuild2(0).get()));
    }

    @LocalData // Some scriptApproval.xml with existing signatures approved
    @Test
    public void reload() throws Exception {
        configureSecurity();
        ScriptApproval sa = ScriptApproval.get();

        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(
                new SecureGroovyScript("jenkins.model.Jenkins.instance", true, null)));
        p.getPublishersList().add(new TestGroovyRecorder(
                new SecureGroovyScript("println(jenkins.model.Jenkins.instance.getLabels())", false, null)));
        r.assertLogNotContains("org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException: "
                        + "Scripts not permitted to use staticMethod jenkins.model.Jenkins getInstance",
                r.assertBuildStatus(Result.SUCCESS, p.scheduleBuild2(0).get()));
        r.assertLogNotContains("org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException: script not yet approved for use",
                r.assertBuildStatus(Result.SUCCESS, p.scheduleBuild2(0).get()));

        ScriptApproval.get().getConfigFile().delete();
        sa.load();
        r.assertLogContains("org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException: script not yet approved for use",
                r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get()));
    }

    @Test
    public void forceSandboxTests() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());

        ScriptApproval.get().setForceSandbox(true);

        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            mockStrategy.grant(p).everywhere().to("devel");
        }

        mockStrategy.grant(Jenkins.READ).everywhere().to("admin");
        mockStrategy.grant(Jenkins.ADMINISTER).everywhere().to("admin");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            mockStrategy.grant(p).everywhere().to("admin");
        }

        r.jenkins.setAuthorizationStrategy(mockStrategy);

        try (ACLContext ctx = ACL.as(User.getById("devel", true))) {
            assertTrue(ScriptApproval.get().isForceSandbox());
            assertTrue(ScriptApproval.get().isForceSandboxForCurrentUser());

            final ApprovalContext ac = ApprovalContext.create();

            //Insert new PendingScript - As the user is not admin and ForceSandbox is enabled, nothing should be added
            {
                ScriptApproval.get().configuring("testScript", GroovyLanguage.get(), ac, true);
                assertTrue(ScriptApproval.get().getPendingScripts().isEmpty());
            }

            //Insert new PendingSignature - As the user is not admin and ForceSandbox is enabled, nothing should be added
            {
                ScriptApproval.get().accessRejected(
                        new RejectedAccessException("testSignatureType", "testSignatureDetails"), ac);
                assertTrue(ScriptApproval.get().getPendingSignatures().isEmpty());
            }

            //Insert new Pending Classpath - As the user is not admin and ForceSandbox is enabled, nothing should be added
            {
                ClasspathEntry cpe = new ClasspathEntry("https://www.jenkins.io");
                ScriptApproval.get().configuring(cpe, ac);
                ScriptApproval.get().addPendingClasspathEntry(
                        new ScriptApproval.PendingClasspathEntry("hash", new URL("https://www.jenkins.io"), ac));
                assertThrows(UnapprovedClasspathException.class, () -> ScriptApproval.get().using(cpe));
                // As we are forcing sandbox, none of the previous operations are able to create new pending ClasspathEntries
                assertTrue(ScriptApproval.get().getPendingClasspathEntries().isEmpty());
            }
        }

        try (ACLContext ctx = ACL.as(User.getById("admin", true))) {
            assertTrue(ScriptApproval.get().isForceSandbox());
            assertFalse(ScriptApproval.get().isForceSandboxForCurrentUser());

            final ApprovalContext ac = ApprovalContext.create();

            //Insert new PendingScript - As the user is admin, the behavior does not change
            {
                ScriptApproval.get().configuring("testScript", GroovyLanguage.get(), ac, true);
                assertEquals(1, ScriptApproval.get().getPendingScripts().size());
            }

            //Insert new PendingSignature -  - As the user is admin, the behavior does not change
            {
                ScriptApproval.get().accessRejected(
                        new RejectedAccessException("testSignatureType", "testSignatureDetails"), ac);
                assertEquals(1, ScriptApproval.get().getPendingSignatures().size());
            }

            //Insert new Pending ClassPatch -  - As the user is admin, the behavior does not change
            {
                ClasspathEntry cpe = new ClasspathEntry("https://www.jenkins.io");
                ScriptApproval.get().configuring(cpe, ac);
                ScriptApproval.get().addPendingClasspathEntry(
                        new ScriptApproval.PendingClasspathEntry("hash", new URL("https://www.jenkins.io"), ac));
                assertEquals(1, ScriptApproval.get().getPendingClasspathEntries().size());
            }
        }
    }

    @Test
    public void forceSandboxScriptSignatureException() throws Exception {
        ScriptApproval.get().setForceSandbox(true);
        FreeStyleProject p = r.createFreeStyleProject("p");
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript("jenkins.model.Jenkins.instance", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        r.assertLogContains("Scripts not permitted to use staticMethod jenkins.model.Jenkins getInstance. " + Messages.ScriptApprovalNoteForceSandBox_message(), b);
    }

    @Test
    public void forceSandboxFormValidation() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().
            grant(Jenkins.READ, Item.READ).everywhere().to("dev").
            grant(Jenkins.ADMINISTER).everywhere().to("admin"));

        try (ACLContext ctx = ACL.as(User.getById("devel", true))) {
            ScriptApproval.get().setForceSandbox(true);
            {
                FormValidation result = ScriptApproval.get().checking("test", GroovyLanguage.get(), false);
                assertEquals(FormValidation.Kind.WARNING, result.kind);
                assertEquals(Messages.ScriptApproval_ForceSandBoxMessage(), result.getMessage());
            }

            ScriptApproval.get().setForceSandbox(false);
            {
                FormValidation result = ScriptApproval.get().checking("test", GroovyLanguage.get(), false);
                assertEquals(FormValidation.Kind.WARNING, result.kind);
                assertEquals(Messages.ScriptApproval_PipelineMessage(), result.getMessage());
            }
        }

        try (ACLContext ctx = ACL.as(User.getById("admin", true))) {

            ScriptApproval.get().setForceSandbox(true);
            {
                FormValidation result = ScriptApproval.get().checking("test", GroovyLanguage.get(), false);
                assertEquals(FormValidation.Kind.OK, result.kind);
                assertTrue(result.getMessage().contains(Messages.ScriptApproval_AdminUserAlert()));

                result = ScriptApproval.get().checking("test", GroovyLanguage.get(), true);
                assertEquals(FormValidation.Kind.OK, result.kind);
                assertTrue(result.getMessage().contains(Messages.ScriptApproval_AdminUserAlert()));
            }

            ScriptApproval.get().setForceSandbox(false);
            {
                FormValidation result = ScriptApproval.get().checking("test", GroovyLanguage.get(), false);
                assertEquals(FormValidation.Kind.OK, result.kind);
                assertFalse(result.getMessage().contains(Messages.ScriptApproval_AdminUserAlert()));

                result = ScriptApproval.get().checking("test", GroovyLanguage.get(), true);
                assertEquals(FormValidation.Kind.OK, result.kind);
                assertFalse(result.getMessage().contains(Messages.ScriptApproval_AdminUserAlert()));
            }
        }
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
            this.groovy = ScriptApproval.get().configuring(groovy, GroovyLanguage.get(), ac, true);
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
