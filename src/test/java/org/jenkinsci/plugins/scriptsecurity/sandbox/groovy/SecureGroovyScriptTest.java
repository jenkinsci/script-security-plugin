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

import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import groovy.lang.Binding;
import hudson.remoting.Which;
import org.apache.tools.ant.AntClassLoader;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlFormUtil;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import hudson.model.FreeStyleProject;
import hudson.model.FreeStyleBuild;
import hudson.model.Item;
import hudson.model.Result;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.Permission;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import jenkins.model.Jenkins;
import jenkins.security.NotReallyRoleSensitiveCallable;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.taskdefs.Expand;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;

import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.kohsuke.groovy.sandbox.impl.Checker;

public class SecureGroovyScriptTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Rule public TemporaryFolder tmpFolderRule = new TemporaryFolder();

    /**
     * Basic approval test where the user doesn't have ADMINISTER privs but has unchecked
     * the sandbox checkbox. Should result in script going to pending approval.
     */
    @Test public void basicApproval() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        FreeStyleProject p = r.createFreeStyleProject("p");
        JenkinsRule.WebClient wc = r.createWebClient();
        wc.login("devel");
        HtmlPage page = wc.getPage(p, "configure");
        HtmlForm config = page.getFormByName("config");
        HtmlFormUtil.getButtonByCaption(config, "Add post-build action").click(); // lib/hudson/project/config-publishers2.jelly
        page.getAnchorByText(r.jenkins.getExtensionList(BuildStepDescriptor.class).get(TestGroovyRecorder.DescriptorImpl.class).getDisplayName()).click();
        wc.waitForBackgroundJavaScript(10000);
        HtmlTextArea script = config.getTextAreaByName("_.script");
        String groovy = "build.externalizableId";
        script.setText(groovy);

        // The fact that the user doesn't have RUN_SCRIPT privs means sandbox mode should be on by default.
        // We need to switch it off to force it into approval.
        HtmlCheckBoxInput sandboxRB = (HtmlCheckBoxInput) config.getInputsByName("_.sandbox").get(0);
        assertEquals(true, sandboxRB.isChecked()); // should be checked
        sandboxRB.setChecked(false); // uncheck sandbox mode => forcing script approval

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


    /**
     * Test where the user has ADMINISTER privs, default to non sandbox mode.
     */
    @Test public void testSandboxDefault_with_ADMINISTER_privs() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        mockStrategy.grant(Jenkins.ADMINISTER).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);
        
        FreeStyleProject p = r.createFreeStyleProject("p");
        JenkinsRule.WebClient wc = r.createWebClient();
        wc.login("devel");
        HtmlPage page = wc.getPage(p, "configure");
        HtmlForm config = page.getFormByName("config");
        HtmlFormUtil.getButtonByCaption(config, "Add post-build action").click(); // lib/hudson/project/config-publishers2.jelly
        page.getAnchorByText(r.jenkins.getExtensionList(BuildStepDescriptor.class).get(TestGroovyRecorder.DescriptorImpl.class).getDisplayName()).click();
        wc.waitForBackgroundJavaScript(10000);
        HtmlTextArea script = config.getTextAreaByName("_.script");
        String groovy = "build.externalizableId";
        script.setText(groovy);
        r.submit(config);
        List<Publisher> publishers = p.getPublishersList();
        assertEquals(1, publishers.size());
        TestGroovyRecorder publisher = (TestGroovyRecorder) publishers.get(0);
        assertEquals(groovy, publisher.getScript().getScript());

        // The user has ADMINISTER privs => should default to non sandboxed
        assertFalse(publisher.getScript().isSandbox());

        // Because it has ADMINISTER privs, the script should not have ended up pending approval
        Set<ScriptApproval.PendingScript> pendingScripts = ScriptApproval.get().getPendingScripts();
        assertEquals(0, pendingScripts.size());

        // Test that the script is executable. If it's not, we will get an UnapprovedUsageException
        assertEquals(groovy, ScriptApproval.get().using(groovy, GroovyLanguage.get()));
    }

    /**
     * Test where the user doesn't have ADMINISTER privs, default to sandbox mode.
     */
    @Test public void testSandboxDefault_without_ADMINISTER_privs() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
       for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        FreeStyleProject p = r.createFreeStyleProject("p");
        JenkinsRule.WebClient wc = r.createWebClient();
        wc.login("devel");
        HtmlPage page = wc.getPage(p, "configure");
        HtmlForm config = page.getFormByName("config");
        HtmlFormUtil.getButtonByCaption(config, "Add post-build action").click(); // lib/hudson/project/config-publishers2.jelly
        page.getAnchorByText(r.jenkins.getExtensionList(BuildStepDescriptor.class).get(TestGroovyRecorder.DescriptorImpl.class).getDisplayName()).click();
        wc.waitForBackgroundJavaScript(10000);
        HtmlTextArea script = config.getTextAreaByName("_.script");
        String groovy = "build.externalizableId";
        script.setText(groovy);
        r.submit(config);
        List<Publisher> publishers = p.getPublishersList();
        assertEquals(1, publishers.size());
        TestGroovyRecorder publisher = (TestGroovyRecorder) publishers.get(0);
        assertEquals(groovy, publisher.getScript().getScript());

        // The user doesn't have ADMINISTER privs => should default to sandboxed mode
        assertTrue(publisher.getScript().isSandbox());

        // When sandboxed, only approved classpath entries are allowed so doesn't get added to pending approvals list.
        // See SecureGroovyScript.configuring(ApprovalContext)
        Set<ScriptApproval.PendingScript> pendingScripts = ScriptApproval.get().getPendingScripts();
        assertEquals(0, pendingScripts.size());

        // We didn't add the approved classpath so ...
        try {
            ScriptApproval.get().using(groovy, GroovyLanguage.get());
            fail("Expected UnapprovedUsageException");
        } catch (UnapprovedUsageException e) {
            assertEquals("script not yet approved for use", e.getMessage());
        }
    }

    private List<File> getAllJarFiles() throws URISyntaxException {
        String testClassPath = String.format(StringUtils.join(getClass().getName().split("\\."), "/"));
        File testClassDir = new File(ClassLoader.getSystemResource(testClassPath).toURI()).getAbsoluteFile();
        
        DirectoryScanner ds = new DirectoryScanner();
        ds.setBasedir(testClassDir);
        ds.setIncludes(new String[]{ "*.jar" });
        ds.scan();
        
        List<File> ret = new ArrayList<File>();
        
        for (String relpath: ds.getIncludedFiles()) {
            ret.add(new File(testClassDir, relpath));
        }
        
        return ret;
    }

    private List<File> copy2TempDir(Iterable<File> files) throws IOException {
        final File tempDir = tmpFolderRule.newFolder();
        final List copies = new ArrayList<File>();
        for (File f: files) {
            final File copy = new File(tempDir, f.getName());
            FileUtils.copyFile(f, copy);
            copies.add(copy);
        }
        return copies;
    }

    private List<ClasspathEntry> files2entries(Iterable<File> files) throws IOException {
        final List entries = new ArrayList<ClasspathEntry>();
        for (File f: files) {
            entries.add(new ClasspathEntry(f.toURI().toURL().toExternalForm()));
        }
        return entries;
    }

    private List<File> getAllUpdatedJarFiles() throws URISyntaxException {
        String testClassPath = String.format(StringUtils.join(getClass().getName().split("\\."), "/"));
        File testClassDir = new File(ClassLoader.getSystemResource(testClassPath).toURI()).getAbsoluteFile();
        
        File updatedDir = new File(testClassDir, "updated");
        
        DirectoryScanner ds = new DirectoryScanner();
        ds.setBasedir(updatedDir);
        ds.setIncludes(new String[]{ "*.jar" });
        ds.scan();
        
        List<File> ret = new ArrayList<File>();
        
        for (String relpath: ds.getIncludedFiles()) {
            ret.add(new File(updatedDir, relpath));
        }
        
        return ret;
    }

    @Test public void testClasspathConfiguration() throws Exception {
        List<ClasspathEntry> classpath = new ArrayList<ClasspathEntry>();
        for (File jarfile: getAllJarFiles()) {
            classpath.add(new ClasspathEntry(jarfile.getAbsolutePath()));
        }
        TestGroovyRecorder recorder = new TestGroovyRecorder(new SecureGroovyScript(
                "whatever",
                true,
                classpath
        ));
        TestGroovyRecorder recorder2 = r.configRoundtrip(recorder);
        r.assertEqualBeans(recorder.getScript(), recorder2.getScript(), "script,sandbox,classpath");
        classpath.clear();
        recorder2 = r.configRoundtrip(recorder);
        r.assertEqualBeans(recorder.getScript(), recorder2.getScript(), "script,sandbox,classpath");
    }

    @Test public void testClasspathInSandbox() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        List<ClasspathEntry> classpath = new ArrayList<ClasspathEntry>();
        for (File jarfile: getAllJarFiles()) {
            classpath.add(new ClasspathEntry(jarfile.getAbsolutePath()));
        }
        
        // Approve classpath.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript("", true, classpath)));
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().approveClasspathEntry(pcp.getHash());
            }
        }
        
        final String testingDisplayName = "TESTDISPLAYNAME";
        
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                    String.format("build.setDisplayName(\"%s\"); \"\";", testingDisplayName),
                    true,
                    classpath
            )));
            
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            // fails for accessing non-whitelisted method.
            r.assertBuildStatus(Result.FAILURE, b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                    String.format(
                            "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                            + "BuildUtil.setDisplayName(build, \"%s\")"
                            + "\"\"", testingDisplayName),
                    true,
                    classpath
            )));
            
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            // fails for accessing non-whitelisted method.
            r.assertBuildStatus(Result.FAILURE, b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                    String.format(
                            "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                            + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                            + "\"\"", testingDisplayName),
                    true,
                    classpath
            )));
            
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
    }
    
    @Test public void testNonapprovedClasspathInSandbox() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        List<ClasspathEntry> classpath = new ArrayList<ClasspathEntry>();
        for (File jarfile: getAllJarFiles()) {
            String path = jarfile.getAbsolutePath();
            classpath.add(new ClasspathEntry(path));
            
            // String hash = ScriptApproval.hashClasspath(path);
            // ScriptApproval.get().addApprovedClasspathEntry(new ScriptApproval.ApprovedClasspathEntry(hash, path));
        }
        
        String SCRIPT_TO_RUN = "\"Script is run\";";
        
        // approve script
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false)));
            
            Set<ScriptApproval.PendingScript> pss = ScriptApproval.get().getPendingScripts();
            assertNotEquals(0, pss.size());
            for(ScriptApproval.PendingScript ps: pss) {
                ScriptApproval.get().approveScript(ps.getHash());
            }
        }
        
        // Success without classpaths
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false)));
            
            r.assertBuildStatusSuccess(p.scheduleBuild2(0).get());
        }
        
        // Fail as the classpath is not approved.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false, classpath)));
            
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        }
        
        // Fail even in sandbox.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, true, classpath)));
            
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        }
        
        // Approve classpath.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript("", true, classpath)));
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().approveClasspathEntry(pcp.getHash());
            }
        }
        
        // Success without sandbox.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false, classpath)));
            
            r.assertBuildStatusSuccess(p.scheduleBuild2(0));
        }
        
        // Success also in  sandbox.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, true, classpath)));
            
            r.assertBuildStatusSuccess(p.scheduleBuild2(0));
        }
    }
    
    @Test public void testUpdatedClasspath() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        // Copy jar files to temporary directory, then overwrite them with updated jar files.
        File tmpDir = tmpFolderRule.newFolder();
        
        for (File jarfile: getAllJarFiles()) {
            FileUtils.copyFileToDirectory(jarfile, tmpDir);
        }
        
        List<ClasspathEntry> classpath = new ArrayList<ClasspathEntry>();
        for (File jarfile: tmpDir.listFiles()) {
            classpath.add(new ClasspathEntry(jarfile.getAbsolutePath()));
        }
        
        String SCRIPT_TO_RUN = "\"Script is run\";";
        
        // approve script
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false)));
            
            Set<ScriptApproval.PendingScript> pss = ScriptApproval.get().getPendingScripts();
            assertNotEquals(0, pss.size());
            for(ScriptApproval.PendingScript ps: pss) {
                ScriptApproval.get().approveScript(ps.getHash());
            }
        }
        
        // Success without classpaths
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false)));
            
            r.assertBuildStatusSuccess(p.scheduleBuild2(0).get());
        }
        
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false, classpath)));
        
        // Fail as the classpath is not approved.
        r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().approveClasspathEntry(pcp.getHash());
            }
        }
        
        // Success as approved.
        r.assertBuildStatusSuccess(p.scheduleBuild2(0));
        
        // overwrite jar files.
        for (File jarfile: getAllUpdatedJarFiles()) {
            FileUtils.copyFileToDirectory(jarfile, tmpDir);
        }
        
        // Fail as the updated jar files are not approved.
        r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().approveClasspathEntry(pcp.getHash());
            }
        }
        
        // Success as approved.
        r.assertBuildStatusSuccess(p.scheduleBuild2(0));
    }
    
    @Test public void testClasspathWithClassDirectory() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        // Copy jar files to temporary directory, then overwrite them with updated jar files.
        File tmpDir = tmpFolderRule.newFolder();
        
        for (File jarfile: getAllJarFiles()) {
            Expand e = new Expand();
            e.setSrc(jarfile);
            e.setDest(tmpDir);
            e.execute();
        }
        
        List<ClasspathEntry> classpath = new ArrayList<ClasspathEntry>();
        classpath.add(new ClasspathEntry(tmpDir.getAbsolutePath()));
        
        final String testingDisplayName = "TESTDISPLAYNAME";
        
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                classpath
        )));
        
        // Fail as the classpath is not approved.
        {
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatus(Result.FAILURE, b);
            r.assertLogNotContains("not yet approved", b);
            r.assertLogContains("is a class directory, which are not allowed", b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        // Unable to approve classpath.
        {
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(0, pcps.size());
        }
    }
    
    @Test public void testDifferentClasspathButSameContent() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        final String testingDisplayName = "TESTDISPLAYNAME";
        
        final List<File> jars = getAllJarFiles();
        
        FreeStyleProject p1 = r.createFreeStyleProject();
        p1.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                files2entries(jars)
        )));
        
        // Fail as the classpath is not approved.
        {
            FreeStyleBuild b = p1.scheduleBuild2(0).get();
            r.assertBuildStatus(Result.FAILURE, b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().approveClasspathEntry(pcp.getHash());
            }
        }
        
        // Success as approved.
        {
            FreeStyleBuild b = p1.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
        
        // New job with jars in other places.
        FreeStyleProject p2 = r.createFreeStyleProject();
        p2.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                files2entries(copy2TempDir(jars))
        )));
        
        // Success as approved.
        {
            FreeStyleBuild b = p2.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
    }
    
    @Test public void testClasspathApproval() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        mockStrategy.grant(Jenkins.READ).everywhere().to("approver");
        mockStrategy.grant(Jenkins.ADMINISTER).everywhere().to("approver");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        		mockStrategy.grant(p).everywhere().to("approver");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);
               
        JenkinsRule.WebClient wc = r.createWebClient();
        
        List<ClasspathEntry> classpath = new ArrayList<ClasspathEntry>();
        
        for (File jarfile: getAllJarFiles()) {
            classpath.add(new ClasspathEntry(jarfile.getAbsolutePath()));
            System.out.println(jarfile);
        }
        
        final String testingDisplayName = "TESTDISPLAYNAME";
        
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                classpath
        )));
        
        // Deny classpath.
        {
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(classpath.size(), pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().denyClasspathEntry(pcp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }

        // If configured by a user with ADMINISTER, the classpath is approved if corresponding checkbox is set
        {
            wc.login("approver");
            HtmlForm config = wc.getPage(p, "configure").getFormByName("config");
            List<HtmlInput> checkboxes = config.getInputsByName("_.shouldBeApproved");
            // Get the last one, because previous ones might be from Lockable Resources during PCT.
            HtmlInput checkbox = checkboxes.get(checkboxes.size() - 1);
            // there's only one classpath being configured, so we only set one checkbox
            checkbox.setChecked(true);
            r.submit(config);
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertEquals(classpath.size(), acps.size());
            
            // cleaning up for next tests
            for(ScriptApproval.ApprovedClasspathEntry acp: acps) {
                ScriptApproval.get().denyApprovedClasspathEntry(acp.getHash());
            }
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }

        // If configured by a user with ADMINISTER, but approval checkbox is not set then approval is requested
        {
            wc.login("approver");
            r.submit(wc.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(classpath.size(), pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertEquals(0, acps.size());

            // cleaning up for next tests
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().denyClasspathEntry(pcp.getHash());
            }
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }

        // If configured by a user without ADMINISTER approval is requested
        {
            wc.login("devel");
            r.submit(wc.getPage(p, "configure").getFormByName("config"));

            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(classpath.size(), pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertEquals(0, acps.size());

            // cleaning up for next tests
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().denyClasspathEntry(pcp.getHash());
            }
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }
        
        // If configured by a user without ADMINISTER while escape hatch in enabled approval is requested 
        {
            wc.login("devel");
            boolean original = ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED;
            ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = true;
            try {
                r.submit(wc.getPage(p, "configure").getFormByName("config"));

                List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
                assertEquals(classpath.size(), pcps.size());
                List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
                assertEquals(0, acps.size());

                // cleaning up for next tests
                for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                    ScriptApproval.get().denyClasspathEntry(pcp.getHash());
                }
                assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
                assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
            } finally {
                ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = original;
            }
        }

        // If configured by a user with ADMINISTER while escape hatch in enabled approval happens upon save
        {
            wc.login("approver");
            boolean original = ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED;
            ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = true;
            try {
                r.submit(wc.getPage(p, "configure").getFormByName("config"));

                List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
                assertEquals(0, pcps.size());
                List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
                assertEquals(classpath.size(), acps.size());

                // cleaning up for next tests
                for(ScriptApproval.ApprovedClasspathEntry acp: acps) {
                    ScriptApproval.get().denyApprovedClasspathEntry(acp.getHash());
                }
                assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
                assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
            } finally {
                ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = original;
            }
        }
        
        // If run with SYSTEM user, an approval is requested.
        {
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());

            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(classpath.size(), pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertEquals(0, acps.size());

            // cleaning up for next tests
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().denyClasspathEntry(pcp.getHash());
            }
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }
    }

    @Test @Issue("SECURITY-2450")
    public void testScriptApproval() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.ADMINISTER).everywhere().to("admin");
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            mockStrategy.grant(p).everywhere().to("admin");
            mockStrategy.grant(p).everywhere().to("devel");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        FreeStyleProject p = r.createFreeStyleProject();
        String initialGroovyScript = "echo 'testScriptApproval'";
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                initialGroovyScript,
                false,
                new ArrayList<>()
        )));

        // clear all pending and approved scripts if there are any
        {
            ScriptApproval.get().preapproveAll();
            ScriptApproval.get().clearApprovedScripts();

            assertEquals(0, ScriptApproval.get().getPendingScripts().size());
            assertEquals(0, ScriptApproval.get().getApprovedScriptHashes().size());
        }

        JenkinsRule.WebClient wc = r.createWebClient();
        
        // If configured by a user with ADMINISTER script is approved if edited by that user
        {
            wc.login("admin");
            HtmlForm config = wc.getPage(p, "configure").getFormByName("config");
            List<HtmlTextArea> scripts = config.getTextAreasByName("_.script");
            // Get the last one, because previous ones might be from Lockable Resources during PCT.
            HtmlTextArea script = scripts.get(scripts.size() - 1);
            String groovy = "echo 'testScriptApproval modified by admin'";
            script.setText(groovy);
            r.submit(config);

            assertTrue(ScriptApproval.get().isScriptApproved(groovy, GroovyLanguage.get()));
            
            // clean up for next tests
            ScriptApproval.get().preapproveAll();
            ScriptApproval.get().clearApprovedScripts();
        }
        
        // If configured by a user without ADMINISTER approval is requested
        {
            wc.login("devel");
            HtmlForm config = wc.getPage(p, "configure").getFormByName("config");
            List<HtmlTextArea> scripts = config.getTextAreasByName("_.script");
            // Get the last one, because previous ones might be from Lockable Resources during PCT.
            HtmlTextArea script = scripts.get(scripts.size() - 1);
            String groovy = "echo 'testScriptApproval modified by devel'";
            script.setText(groovy);
            r.submit(config);

            assertFalse(ScriptApproval.get().isScriptApproved(groovy, GroovyLanguage.get()));
            assertEquals(1, ScriptApproval.get().getPendingScripts().size());

            // clean up for next tests
            ScriptApproval.get().preapproveAll();
            ScriptApproval.get().clearApprovedScripts();
        }
        
        // If configured by a user with ADMINISTER while escape hatch is on script is approved upon save
        {
            wc.login("admin");
            boolean original = ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED;
            ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = true;
            try {
                HtmlForm config = wc.getPage(p, "configure").getFormByName("config");
                List<HtmlTextArea> scripts = config.getTextAreasByName("_.script");
                // Get the last one, because previous ones might be from Lockable Resources during PCT.
                HtmlTextArea script = scripts.get(scripts.size() - 1);
                String currentScriptValue = script.getText();
                r.submit(config);

                assertTrue(ScriptApproval.get().isScriptApproved(currentScriptValue, GroovyLanguage.get()));

                // clean up for next tests
                ScriptApproval.get().preapproveAll();
                ScriptApproval.get().clearApprovedScripts();
            } finally {
                ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = original;
            }
        }

        // If configured by a user without ADMINISTER while escape hatch is on script is not approved
        {
            wc.login("devel");
            boolean original = ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED;
            ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = true;
            try {
                r.submit(wc.getPage(p, "configure").getFormByName("config"));

                assertFalse(ScriptApproval.get().isScriptApproved(initialGroovyScript, GroovyLanguage.get()));

                // clean up for next tests
                ScriptApproval.get().preapproveAll();
                ScriptApproval.get().clearApprovedScripts();
            } finally {
                ScriptApproval.ADMIN_AUTO_APPROVAL_ENABLED = original;
            }
        }
    }

    @Test @Issue("JENKINS-25348")
    public void testSandboxClassResolution() throws Exception {
        File jar = Which.jarFile(Checker.class);

        // this child-first classloader creates an environment in which another groovy-sandbox exists
        AntClassLoader a = new AntClassLoader(getClass().getClassLoader(),false);
        a.addPathComponent(jar);

        // make sure we are loading two different copies now
        assertNotSame(Checker.class, a.loadClass(Checker.class.getName()));

        SecureGroovyScript sgs = new SecureGroovyScript("System.gc()", true, null);
        try {
            sgs.configuringWithKeyItem().evaluate(a, new Binding());
            fail("Expecting a rejection");
        } catch (RejectedAccessException e) {
            assertTrue(e.getMessage().contains("staticMethod java.lang.System gc"));
        }
    }
    
    @Issue("SECURITY-1186")
    @Test public void testFinalizersForbiddenInSandbox() throws Exception {
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(
                new SecureGroovyScript("class Test { public void finalize() { } }; null", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        r.assertLogContains("Object.finalize()", b);
    }

    @Issue("SECURITY-1186")
    @Test public void testFinalizersAllowedWithWholeScriptApproval() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("dev");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            mockStrategy.grant(p).everywhere().to("dev");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);

        final FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(
                new SecureGroovyScript("class Test { public void finalize() { } }; null", false, null)));

        ACL.impersonate(User.getById("dev", true).impersonate(), new NotReallyRoleSensitiveCallable<Void, Exception>() {
            public Void call() throws Exception {
                FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
                r.assertLogContains("UnapprovedUsageException", b);
                return null;
            }
        });

        Set<ScriptApproval.PendingScript> ps = ScriptApproval.get().getPendingScripts();
        assertEquals(1, ps.size());
        ScriptApproval.get().approveScript(ps.iterator().next().getHash());

        ACL.impersonate(User.getById("dev", true).impersonate(), new NotReallyRoleSensitiveCallable<Void, Exception>() {
            public Void call() throws Exception {
                r.assertBuildStatus(Result.SUCCESS, p.scheduleBuild2(0));
                return null;
            }
        });
    }

    @Issue("SECURITY-1292")
    @Test
    public void blockASTTest() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("import groovy.transform.*\n" +
                "import jenkins.model.Jenkins\n" +
                "import hudson.model.FreeStyleProject\n" +
                "@ASTTest(value={ assert Jenkins.getInstance().createProject(FreeStyleProject.class, \"should-not-exist\") })\n" +
                "@Field int x\n" +
                "echo 'hello'\n", false, null).toString(), containsString("Annotation ASTTest cannot be used in the sandbox"));

        assertNull(r.jenkins.getItem("should-not-exist"));
    }

    @Issue("SECURITY-1292")
    @Test
    public void blockGrab() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("@Grab(group='foo', module='bar', version='1.0')\ndef foo\n", false, null).toString(),
                containsString("Annotation Grab cannot be used in the sandbox"));
    }

    @Issue("SECURITY-1318")
    @Test
    public void blockGrapes() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("@Grapes([@Grab(group='foo', module='bar', version='1.0')])\ndef foo\n", false, null).toString(),
                containsString("Annotation Grapes cannot be used in the sandbox"));
    }

    @Issue("SECURITY-1318")
    @Test
    public void blockGrabConfig() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("@GrabConfig(autoDownload=false)\ndef foo\n", false, null).toString(),
                containsString("Annotation GrabConfig cannot be used in the sandbox"));
    }

    @Issue("SECURITY-1318")
    @Test
    public void blockGrabExclude() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("@GrabExclude(group='org.mortbay.jetty', module='jetty-util')\ndef foo\n", false, null).toString(),
                containsString("Annotation GrabExclude cannot be used in the sandbox"));
    }

    @Issue("SECURITY-1319")
    @Test
    public void blockGrabResolver() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("@GrabResolver(name='restlet.org', root='http://maven.restlet.org')\ndef foo\n", false, null).toString(),
                containsString("Annotation GrabResolver cannot be used in the sandbox"));
    }

    @Issue("SECURITY-1318")
    @Test
    public void blockArbitraryAnnotation() throws Exception {
        try {
            System.setProperty(RejectASTTransformsCustomizer.class.getName() + ".ADDITIONAL_BLOCKED_TRANSFORMS", "groovy.transform.Field,groovy.transform.Immutable");
            SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
            assertThat(d.doCheckScript("@Field\ndef foo\n", false, null).toString(),
                    containsString("Annotation Field cannot be used in the sandbox"));
        } finally {
            System.clearProperty(RejectASTTransformsCustomizer.class.getName() + ".ADDITIONAL_BLOCKED_TRANSFORMS");
        }
    }

    @Issue("SECURITY-1321")
    @Test
    public void blockAnnotationCollector() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("import groovy.transform.*\n" +
                "import jenkins.model.Jenkins\n" +
                "import hudson.model.FreeStyleProject\n" +
                "@AnnotationCollector([ASTTest]) @interface Lol {}\n" +
                "@Lol(value={ assert Jenkins.getInstance().createProject(FreeStyleProject.class, \"should-not-exist\") })\n" +
                "@Field int x\n" +
                "echo 'hello'\n", false, null).toString(), containsString("Annotation AnnotationCollector cannot be used in the sandbox"));

        assertNull(r.jenkins.getItem("should-not-exist"));
    }

    @Issue("SECURITY-1320")
    @Test
    public void blockFQCN() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("import groovy.transform.*\n" +
                "import jenkins.model.Jenkins\n" +
                "import hudson.model.FreeStyleProject\n" +
                "@groovy.transform.ASTTest(value={ assert Jenkins.getInstance().createProject(FreeStyleProject.class, \"should-not-exist\") })\n" +
                "@Field int x\n" +
                "echo 'hello'\n", false, null).toString(), containsString("Annotation groovy.transform.ASTTest cannot be used in the sandbox"));

        assertNull(r.jenkins.getItem("should-not-exist"));
    }

    @Issue("SECURITY-1320")
    @Test
    public void blockImportAsBlockedAnnotation() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("import groovy.transform.ASTTest as lolwut\n" +
                "import jenkins.model.Jenkins\n" +
                "import hudson.model.FreeStyleProject\n" +
                "@lolwut(value={ assert Jenkins.getInstance().createProject(FreeStyleProject.class, \"should-not-exist\") })\n" +
                "int x\n" +
                "echo 'hello'\n", false, null).toString(), containsString("Annotation groovy.transform.ASTTest cannot be used in the sandbox"));

        assertNull(r.jenkins.getItem("should-not-exist"));
    }

    @Issue("SECURITY-1336")
    @Test
    public void blockConstructorInvocationInCheck() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("import jenkins.model.Jenkins\n" +
                "import hudson.model.FreeStyleProject\n" +
                "public class DoNotRunConstructor {\n" +
                "  public DoNotRunConstructor() {\n" +
                "    assert Jenkins.getInstance().createProject(FreeStyleProject.class, \"should-not-exist\")\n" +
                "  }\n" +
                "}\n", false, null).toString(), containsString("OK"));

        assertNull(r.jenkins.getItem("should-not-exist"));
    }

    @Issue("SECURITY-1336")
    @Test
    public void blockConstructorInvocationAtRuntime() throws Exception {
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
            "class DoNotRunConstructor {\n" +
            "  static void main(String[] args) {}\n" +
            "  DoNotRunConstructor() {\n" +
            "    assert jenkins.model.Jenkins.instance.createProject(hudson.model.FreeStyleProject, 'should-not-exist')\n" +
            "  }\n" +
            "}\n", true, null)));
        FreeStyleBuild b = p.scheduleBuild2(0).get();
        assertNull(r.jenkins.getItem("should-not-exist"));
        r.assertBuildStatus(Result.FAILURE, b);
        r.assertLogContains("staticMethod jenkins.model.Jenkins getInstance", b);
    }

    @Issue("JENKINS-56682")
    @Test
    public void testScriptAtFieldInitializers() throws Exception {
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "import groovy.transform.Field\n" +
                "@Field foo = 1\n" +
                "@Field bar = foo + 1\n" + // evaluated during GroovyShell.parse
                "if (bar != 2) {\n" +
                "  throw new Exception('oops')\n" +
                "}\n", true, null)));
        r.buildAndAssertSuccess(p);
    }

    @Issue("SECURITY-1465")
    @Test public void blockLhsInMethodPointerExpression() throws Exception {
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "({" +
                "  System.getProperties()\n" +
                "  1" +
                "}().&toString)()", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        r.assertLogContains("staticMethod java.lang.System getProperties", b);
    }

    @Issue("SECURITY-1465")
    @Test public void blockRhsInMethodPointerExpression() throws Exception {
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "1.&(System.getProperty('sandboxTransformsMethodPointerRhs'))()", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        r.assertLogContains("staticMethod java.lang.System getProperty java.lang.String", b);
    }

    @Issue("SECURITY-1465")
    @Test public void blockCastingUnsafeUserDefinedImplementationsOfCollection() throws Exception {
        // See additional info on this test case in `SandboxTransformerTest.sandboxWillNotCastNonStandardCollections()` over in groovy-sandbox.
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "def i = 0\n" +
                "(({-> if(i) {\n" +
                "    return ['secret.txt'] as Object[]\n" +
                "  } else {\n" +
                "    i = 1\n" +
                "    return null\n" +
                "  }\n" +
                "} as Collection) as File) as Object[]", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        // Before the security fix, fails with FileNotFoundException, bypassing the sandbox!
        r.assertLogContains("Casting non-standard Collections to a type via constructor is not supported", b);
    }

    @Issue("SECURITY-1465")
    @Test public void blockCastingSafeUserDefinedImplementationsOfCollection() throws Exception {
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "({-> return ['secret.txt'] as Object[]} as Collection) as File", true, null)));
        FreeStyleBuild b = r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        // Before the security fix, fails because `new File(String)` is not whitelisted, so not a problem, but we have
        // no good way to distinguish this case from the one in blockCastingUnsafeUserDefinedImplementationsOfCollection.
        r.assertLogContains("Casting non-standard Collections to a type via constructor is not supported", b);
    }

    @Issue("SECURITY-1465")
    @Test public void blockEnumConstants() throws Exception {
        FreeStyleProject p1 = r.createFreeStyleProject();
        p1.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "jenkins.YesNoMaybe.MAYBE", true, null)));
        FreeStyleBuild b1 = r.assertBuildStatus(Result.FAILURE, p1.scheduleBuild2(0));
        r.assertLogContains("staticField jenkins.YesNoMaybe MAYBE", b1);

        FreeStyleProject p2 = r.createFreeStyleProject();
        p2.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "if ((jenkins.YesNoMaybe.class as Object[]).size() != 3) throw new Exception('blocked enum access')", true, null)));
        FreeStyleBuild b2 = r.assertBuildStatus(Result.FAILURE, p2.scheduleBuild2(0));
        r.assertLogContains("staticField jenkins.YesNoMaybe YES", b2);
    }
}
