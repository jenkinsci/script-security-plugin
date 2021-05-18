/*
 * The MIT License
 *
 * Copyright 2019 CloudBees, Inc.
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

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.html.DomNodeUtil;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Result;
import jenkins.model.Jenkins;
import static org.hamcrest.Matchers.*;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.TestGroovyRecorder;
import org.junit.ClassRule;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.BuildWatcher;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class ScriptApprovalNoteTest {

    @ClassRule public static BuildWatcher buildWatcher = new BuildWatcher();

    @Rule public JenkinsRule r = new JenkinsRule();

    @Issue("JENKINS-34973")
    @Test public void smokes() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().
            grant(Jenkins.ADMINISTER, Jenkins.READ, Item.READ).everywhere().to("adminUser").
            grant(Jenkins.READ, Item.READ).everywhere().to("otherUser"));
        FreeStyleProject p = r.createFreeStyleProject("p");
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript("jenkins.model.Jenkins.instance", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        r.assertLogContains("org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException: Scripts not permitted to use staticMethod jenkins.model.Jenkins getInstance", b);
        r.assertLogContains("Scripts not permitted to use staticMethod jenkins.model.Jenkins getInstance. " + Messages.ScriptApprovalNote_message(), b);
        
        JenkinsRule.WebClient wc = r.createWebClient();

        wc.login("adminUser");
        // make sure we see the annotation for the ADMINISTER user.
        HtmlPage rsp = wc.getPage(b, "console");
        assertEquals(1, DomNodeUtil.selectNodes(rsp, "//A[@href='" + r.contextPath + "/scriptApproval']").size());

        // make sure raw console output doesn't include the garbage and has the right message.
        TextPage raw = (TextPage)wc.goTo(b.getUrl()+"consoleText","text/plain");
        assertThat(raw.getContent(), containsString(" getInstance. " + Messages.ScriptApprovalNote_message()));

        wc.login("otherUser");
        // make sure we don't see the link for the other user.
        HtmlPage rsp2 = wc.getPage(b, "console");
        assertEquals(0, DomNodeUtil.selectNodes(rsp2, "//A[@href='" + r.contextPath + "/scriptApproval']").size());

        // make sure raw console output doesn't include the garbage and has the right message.
        TextPage raw2 = (TextPage)wc.goTo(b.getUrl()+"consoleText","text/plain");
        assertThat(raw2.getContent(), containsString(" getInstance. " + Messages.ScriptApprovalNote_message()));
    }

}
