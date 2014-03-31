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

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Result;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import java.util.List;
import java.util.Set;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class SecureGroovyScriptTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void basicApproval() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        FreeStyleProject p = r.createFreeStyleProject("p");
        JenkinsRule.WebClient wc = r.createWebClient();
        wc.login("devel");
        HtmlPage page = wc.getPage(p, "configure");
        HtmlForm config = page.getFormByName("config");
        config.getButtonByCaption("Add post-build action").click(); // lib/hudson/project/config-publishers2.jelly
        page.getAnchorByText(r.jenkins.getExtensionList(BuildStepDescriptor.class).get(TestGroovyRecorder.DescriptorImpl.class).getDisplayName()).click();
        HtmlTextArea script = config.getTextAreaByName("_.script");
        String groovy = "build.externalizableId";
        script.setText(groovy);
        r.submit(config);
        List<Publisher> publishers = p.getPublishersList();
        assertEquals(1, publishers.size());
        TestGroovyRecorder publisher = (TestGroovyRecorder) publishers.get(0);
        assertEquals(groovy, publisher.getScript().getScript());
        assertFalse(publisher.getScript().isSandbox());
        Set<ScriptApproval.PendingScript> pendingScripts = ScriptApproval.get().getPendingScripts();
        assertEquals(1, pendingScripts.size());
        ScriptApproval.PendingScript pendingScript = pendingScripts.iterator().next();
        assertEquals(groovy, pendingScript.script);
        assertEquals(p, pendingScript.getContext().getItem());
        assertEquals("devel", pendingScript.getContext().getUser());
        r.assertLogContains(UnapprovedUsageException.class.getName(), r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get()));
        page = wc.getPage(p, "configure");
        config = page.getFormByName("config");
        script = config.getTextAreaByName("_.script");
        groovy = "build.externalizableId.toUpperCase()";
        script.setText(groovy);
        r.submit(config);
        pendingScripts = ScriptApproval.get().getPendingScripts();
        assertEquals(1, pendingScripts.size());
        pendingScript = pendingScripts.iterator().next();
        assertEquals(groovy, pendingScript.script);
        ScriptApproval.get().approveScript(pendingScript.getHash());
        pendingScripts = ScriptApproval.get().getPendingScripts();
        assertEquals(0, pendingScripts.size());
        assertEquals("P#2", r.assertBuildStatusSuccess(p.scheduleBuild2(0)).getDescription());
        r.jenkins.reload();
        p = r.jenkins.getItemByFullName("p", FreeStyleProject.class);
        assertEquals("P#3", r.assertBuildStatusSuccess(p.scheduleBuild2(0)).getDescription());
    }

}
