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

import com.gargoylesoftware.htmlunit.html.HtmlElement;
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
import java.util.TreeSet;
import org.jvnet.hudson.test.WithoutJenkins;

public class ScriptApprovalTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Rule public TemporaryFolder tmpFolderRule = new TemporaryFolder();

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

    private ClasspathEntry entry(File f) throws Exception {
        return new ClasspathEntry(f.toURI().toURL().toExternalForm());
    }

    private void configure(ClasspathEntry entry) {
        ScriptApproval.get().configuring(entry, ApprovalContext.create());
    }

    private void configureAndUse(ClasspathEntry entry) throws Exception {
        configure(entry);
        ScriptApproval.get().using(entry);
    }

    /** Returns the number of entries the pending list have been increased. */
    private int configureButCantUse(ClasspathEntry entry) throws Exception {
        final int initialSize = ScriptApproval.get().getPendingClasspathEntries().size();
        configure(entry);
        try {
            configureAndUse(entry);
        } catch(UnapprovedClasspathException e) {
            return ScriptApproval.get().getPendingClasspathEntries().size() - initialSize;
        }
        fail("Classpath entry " + entry.getURL() + " should have been rejected");
        return 0;
    }

    @Test public void classPathEntryWithNoSecurity() throws Exception {
        configureAndUse(entry(tmpFolderRule.newFile()));
    }

    @Test public void classPathEntryRejectedEvenWithNoSecurity() throws Exception {
        // It does not go to the pending list.
        assertEquals(0, configureButCantUse(entry(tmpFolderRule.newFolder())));
    }

    // http://stackoverflow.com/a/25393190/12916
    @WithoutJenkins
    @Test public void getPendingClasspathEntry() throws Exception {
        TreeSet<ScriptApproval.PendingClasspathEntry> pendingClasspathEntries = new TreeSet<ScriptApproval.PendingClasspathEntry>();
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
        
        ScriptApproval.get().addApprovedClasspathEntry(new ScriptApproval.ApprovedClasspathEntry(CLASSPATH_HASH1, CLASSPATH_PATH1));
        ScriptApproval.get().addApprovedClasspathEntry(new ScriptApproval.ApprovedClasspathEntry(CLASSPATH_HASH2, CLASSPATH_PATH2));
        ScriptApproval.get().addPendingClasspathEntry(new ScriptApproval.PendingClasspathEntry(CLASSPATH_HASH3, CLASSPATH_PATH3, context));
        ScriptApproval.get().addPendingClasspathEntry(new ScriptApproval.PendingClasspathEntry(CLASSPATH_HASH4, CLASSPATH_PATH4, context));
        ScriptApproval.get().addPendingClasspathEntry(new ScriptApproval.PendingClasspathEntry(CLASSPATH_HASH5, CLASSPATH_PATH5, context));
        
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
        click(page, String.format("pcp-%s", CLASSPATH_HASH3), "approve");

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
        click(page, String.format("pcp-%s", CLASSPATH_HASH4), "deny");
        
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
        click(page, String.format("acp-%s", CLASSPATH_HASH1), "delete");

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
        clickAndWait(page.getElementById("approvedClasspathEntries-clear")
            .getElementsByTagName("button").get(0));
        
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

    private void clickAndWait(HtmlElement e) throws IOException {
        e.click();
        e.getPage().getWebClient().waitForBackgroundJavaScript(10000);
    }

    private void click(HtmlPage page, String id, String value) throws IOException {
        for (HtmlElement e : page.getElementById(id).getElementsByTagName("button")) {
            if (e.hasAttribute("class") && value.equals(e.getAttribute("class"))) {
                clickAndWait(e);
                return;
            }
        }
        throw new AssertionError(String.format("Unable to find button with class [%s] in element [%s]", value, id));
    }

}
