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

import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;
import com.gargoylesoftware.htmlunit.ConfirmHandler;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import java.net.URL;

public class ScriptApprovalTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void emptyScript() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        configureAndUse("");
    }

    @Test public void noSecurity() throws Exception {
        configureAndUse("whatever");
    }

    @Test(expected=UnapprovedUsageException.class) public void withSecurity() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        configureAndUse("whatever");
    }

    private void configureAndUse(String groovy) {
        ScriptApproval.get().configuring(groovy, GroovyLanguage.get(), ApprovalContext.create());
        assertEquals(groovy, ScriptApproval.get().using(groovy, GroovyLanguage.get()));
    }
    
    @Test public void approveClasspaths() throws Exception {
        final String CLASSPATH_HASH1 = "0000000000000000000000000000000000000000";
        final URL CLASSPATH_PATH1 = new URL("file:/path/to/some/jar1.jar");
        final String CLASSPATH_HASH2 = "1234567890abcdef1234567890abcdef12345678";
        final URL CLASSPATH_PATH2 = new URL("file:/path/to/some/classpath2");
        final String CLASSPATH_HASH3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        final URL CLASSPATH_PATH3 = new URL("file:/path/to/some/jar3.jar");
        final String CLASSPATH_HASH4 = "abcdef1234567890abcdef1234567890abcdef12";
        final URL CLASSPATH_PATH4 = new URL("file:/path/to/some/classpath4");
        final String CLASSPATH_HASH5 = "9999999999999999999999999999999999999999";
        final URL CLASSPATH_PATH5 = new URL("file:/path/to/some/jar5.jar");
        
        ApprovalContext context = ApprovalContext.create();
        
        ScriptApproval.get().addApprovedClasspath(new ScriptApproval.ApprovedClasspath(CLASSPATH_HASH1, CLASSPATH_PATH1));
        ScriptApproval.get().addApprovedClasspath(new ScriptApproval.ApprovedClasspath(CLASSPATH_HASH2, CLASSPATH_PATH2));
        ScriptApproval.get().addPendingClasspath(new ScriptApproval.PendingClasspath(CLASSPATH_HASH3, CLASSPATH_PATH3, context));
        ScriptApproval.get().addPendingClasspath(new ScriptApproval.PendingClasspath(CLASSPATH_HASH4, CLASSPATH_PATH4, context));
        ScriptApproval.get().addPendingClasspath(new ScriptApproval.PendingClasspath(CLASSPATH_HASH5, CLASSPATH_PATH5, context));
        
        JenkinsRule.WebClient wc = r.createWebClient();
        
        // click "OK" for all confirms.
        wc.setConfirmHandler(new ConfirmHandler() {
            public boolean handleConfirm(Page page, String message) {
                return true;
            }
        });
        
        HtmlPage page = wc.goTo(ScriptApproval.get().getUrlName());
        
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH1)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH2)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH4)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH5)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH1)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH2)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH3)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH4)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH5)));
        
        // approve a classpath
        page.getElementById(String.format("pcp-%s", CLASSPATH_HASH3))
            .getElementsByAttribute("button", "class", "approve").get(0).click();
        
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH1)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH2)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH4)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH5)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH1)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH2)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH3)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH4)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH5)));
        
        // deny a classpath
        page.getElementById(String.format("pcp-%s", CLASSPATH_HASH4))
            .getElementsByAttribute("button", "class", "deny").get(0).click();
        
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH1)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH2)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH4)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH5)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH1)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH2)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH4)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH5)));
        
        // delete a classpath
        page.getElementById(String.format("acp-%s", CLASSPATH_HASH1))
            .getElementsByAttribute("button", "class", "delete").get(0).click();
        
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH1)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH2)));
        assertNotNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH4)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH5)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH1)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH2)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH4)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH5)));
        
        // clear all classpaths
        page.getElementById("approvedClasspaths-clear")
            .getElementsByTagName("button").get(0).click();
        
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH1)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH2)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH4)));
        assertNull(page.getElementById(String.format("acp-%s", CLASSPATH_HASH5)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH1)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH2)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH3)));
        assertNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH4)));
        assertNotNull(page.getElementById(String.format("pcp-%s", CLASSPATH_HASH5)));
    }

}
