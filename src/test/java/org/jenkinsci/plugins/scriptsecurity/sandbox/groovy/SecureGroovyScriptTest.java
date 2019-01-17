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
     * Basic approval test where the user doesn't have RUN_SCRIPTS privs but has unchecked
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
     * Test where the user has RUN_SCRIPTS privs, default to non sandbox mode.
     */
    @Test public void testSandboxDefault_with_RUN_SCRIPTS_privs() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        mockStrategy.grant(Jenkins.RUN_SCRIPTS).everywhere().to("devel");
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

        // The user has RUN_SCRIPTS privs => should default to non sandboxed
        assertFalse(publisher.getScript().isSandbox());

        // Because it has RUN_SCRIPTS privs, the script should not have ended up pending approval
        Set<ScriptApproval.PendingScript> pendingScripts = ScriptApproval.get().getPendingScripts();
        assertEquals(0, pendingScripts.size());

        // Test that the script is executable. If it's not, we will get an UnapprovedUsageException
        assertEquals(groovy, ScriptApproval.get().using(groovy, GroovyLanguage.get()));
    }

    /**
     * Test where the user doesn't have RUN_SCRIPTS privs, default to sandbox mode.
     */
    @Test public void testSandboxDefault_without_RUN_SCRIPTS_privs() throws Exception {
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

        // The user doesn't have RUN_SCRIPTS privs => should default to sandboxed mode
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
        r.assertEqualDataBoundBeans(recorder, recorder2);
        classpath.clear();
        recorder2 = r.configRoundtrip(recorder);
        r.assertEqualDataBoundBeans(recorder, recorder2);
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
    
    @Test public void testClasspathAutomaticApprove() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        
        MockAuthorizationStrategy mockStrategy = new MockAuthorizationStrategy();
        mockStrategy.grant(Jenkins.READ).everywhere().to("devel");
        mockStrategy.grant(Jenkins.READ).everywhere().to("approver");
        mockStrategy.grant(Jenkins.RUN_SCRIPTS).everywhere().to("approver");
        mockStrategy.grant(Jenkins.ADMINISTER).everywhere().to("approver");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
        		mockStrategy.grant(p).everywhere().to("devel");
        		mockStrategy.grant(p).everywhere().to("approver");
        }
        r.jenkins.setAuthorizationStrategy(mockStrategy);
               
        JenkinsRule.WebClient wcDevel = r.createWebClient();
        wcDevel.login("devel");
        
        JenkinsRule.WebClient wcApprover = r.createWebClient();
        wcApprover.login("approver");
        
        
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
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().denyClasspathEntry(pcp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }
        
        // If configured by a user with RUN_SCRIPTS, the classpath is automatically approved
        {
            r.submit(wcApprover.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertNotEquals(0, acps.size());
            
            for(ScriptApproval.ApprovedClasspathEntry acp: acps) {
                ScriptApproval.get().denyApprovedClasspathEntry(acp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }
        
        // If configured by a user without RUN_SCRIPTS, approval is requested
        {
            r.submit(wcDevel.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertEquals(0, acps.size());
            
            // don't remove pending classpaths.
        }
        
        // If configured by a user with RUN_SCRIPTS, the classpath is automatically approved, and removed from approval request.
        {
            assertNotEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
            
            r.submit(wcApprover.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertNotEquals(0, acps.size());
            
            for(ScriptApproval.ApprovedClasspathEntry acp: acps) {
                ScriptApproval.get().denyApprovedClasspathEntry(acp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
        }
        
        // If run with SYSTEM user, an approval is requested.
        {
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
            
            List<ScriptApproval.PendingClasspathEntry> pcps = ScriptApproval.get().getPendingClasspathEntries();
            assertNotEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspathEntry> acps = ScriptApproval.get().getApprovedClasspathEntries();
            assertEquals(0, acps.size());
            
            for(ScriptApproval.PendingClasspathEntry pcp: pcps) {
                ScriptApproval.get().denyClasspathEntry(pcp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspathEntries().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspathEntries().size());
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
                "echo 'hello'\n", false).toString(), containsString("Annotation ASTTest cannot be used in the sandbox"));

        assertNull(r.jenkins.getItem("should-not-exist"));
    }

    @Issue("SECURITY-1292")
    @Test
    public void blockGrab() throws Exception {
        SecureGroovyScript.DescriptorImpl d = r.jenkins.getDescriptorByType(SecureGroovyScript.DescriptorImpl.class);
        assertThat(d.doCheckScript("@Grab(group='foo', module='bar', version='1.0')\ndef foo\n", false).toString(),
                containsString("Annotation Grab cannot be used in the sandbox"));
    }


}
