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

import org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import hudson.model.FreeStyleProject;
import hudson.model.FreeStyleBuild;
import hudson.model.Item;
import hudson.model.Result;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import java.io.File;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import jenkins.model.Jenkins;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.taskdefs.Expand;
import org.apache.tools.ant.taskdefs.Touch;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.UnapprovedUsageException;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.JenkinsRule;

public class SecureGroovyScriptTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Rule public TemporaryFolder tmpFolderRule = new TemporaryFolder();
 
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
        List<ClasspathEntry> classpathList = new ArrayList<ClasspathEntry>();
        for (File jarfile: getAllJarFiles()) {
            classpathList.add(new ClasspathEntry(jarfile.getAbsolutePath()));
        }
        
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                "whatever",
                true,
                classpathList
        )));
        
        JenkinsRule.WebClient wc = r.createWebClient();
        r.submit(wc.getPage(p, "configure").getFormByName("config"));
        
        p = r.jenkins.getItemByFullName(p.getFullName(), FreeStyleProject.class);
        TestGroovyRecorder recorder = (TestGroovyRecorder)p.getPublishersList().get(0);
        assertEquals(classpathList, recorder.getScript().getClasspath());
    }

    @Test public void testClasspathInSandbox() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        
        List<ClasspathEntry> classpathList = new ArrayList<ClasspathEntry>();
        for (File jarfile: getAllJarFiles()) {
            classpathList.add(new ClasspathEntry(jarfile.getAbsolutePath()));
        }
        
        // Approve classpath.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript("", true, classpathList)));
            
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
            }
        }
        
        final String testingDisplayName = "TESTDISPLAYNAME";
        
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                    String.format("build.setDisplayName(\"%s\"); \"\";", testingDisplayName),
                    true,
                    classpathList
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
                    classpathList
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
                    classpathList
            )));
            
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
    }
    
    @Test public void testNonapprovedClasspathInSandbox() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        
        List<ClasspathEntry> classpathList = new ArrayList<ClasspathEntry>();
        for (File jarfile: getAllJarFiles()) {
            String path = jarfile.getAbsolutePath();
            classpathList.add(new ClasspathEntry(path));
            
            // String hash = ScriptApproval.hashClasspath(path);
            // ScriptApproval.get().addApprovedClasspath(new ScriptApproval.ApprovedClasspath(hash, path));
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
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false, classpathList)));
            
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        }
        
        // Fail even in sandbox.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, true, classpathList)));
            
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        }
        
        // Approve classpath.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript("", true, classpathList)));
            
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
            }
        }
        
        // Success without sandbox.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false, classpathList)));
            
            r.assertBuildStatusSuccess(p.scheduleBuild2(0));
        }
        
        // Success also in  sandbox.
        {
            FreeStyleProject p = r.createFreeStyleProject();
            p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, true, classpathList)));
            
            r.assertBuildStatusSuccess(p.scheduleBuild2(0));
        }
    }
    
    @Test public void testUpdatedClasspath() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        
        // Copy jar files to temporary directory, then overwrite them with updated jar files.
        File tmpDir = tmpFolderRule.newFolder();
        
        for (File jarfile: getAllJarFiles()) {
            FileUtils.copyFileToDirectory(jarfile, tmpDir);
        }
        
        List<ClasspathEntry> classpathList = new ArrayList<ClasspathEntry>();
        for (File jarfile: tmpDir.listFiles()) {
            classpathList.add(new ClasspathEntry(jarfile.getAbsolutePath()));
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
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(SCRIPT_TO_RUN, false, classpathList)));
        
        // Fail as the classpath is not approved.
        r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
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
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
            }
        }
        
        // Success as approved.
        r.assertBuildStatusSuccess(p.scheduleBuild2(0));
    }
    
    @Test public void testClasspathWithClassDirectory() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        
        // Copy jar files to temporary directory, then overwrite them with updated jar files.
        File tmpDir = tmpFolderRule.newFolder();
        
        for (File jarfile: getAllJarFiles()) {
            Expand e = new Expand();
            e.setSrc(jarfile);
            e.setDest(tmpDir);
            e.execute();
        }
        
        List<ClasspathEntry> classpathList = new ArrayList<ClasspathEntry>();
        classpathList.add(new ClasspathEntry(tmpDir.getAbsolutePath()));
        
        final String testingDisplayName = "TESTDISPLAYNAME";
        
        FreeStyleProject p = r.createFreeStyleProject();
        p.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                classpathList
        )));
        
        // Fail as the classpath is not approved.
        {
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatus(Result.FAILURE, b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
            }
        }
        
        // Success as approved.
        {
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
        
        // add new file in tmpDir.
        {
            File f = tmpFolderRule.newFile();
            FileUtils.copyFileToDirectory(f, tmpDir);
        }
        
        // Fail as the class directory is updated.
        {
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatus(Result.FAILURE, b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
            }
        }
        
        // Success as approved.
        {
            FreeStyleBuild b = p.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
    }
    
    @Test public void testDifferentClasspathButSameContent() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        
        final String testingDisplayName = "TESTDISPLAYNAME";
        
        File tmpDir1 = tmpFolderRule.newFolder();
        
        for (File jarfile: getAllJarFiles()) {
            Expand e = new Expand();
            e.setSrc(jarfile);
            e.setDest(tmpDir1);
            e.execute();
        }
        
        List<ClasspathEntry> classpathList1 = new ArrayList<ClasspathEntry>();
        classpathList1.add(new ClasspathEntry(tmpDir1.getAbsolutePath()));
        
        FreeStyleProject p1 = r.createFreeStyleProject();
        p1.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                classpathList1
        )));
        
        // Fail as the classpath is not approved.
        {
            FreeStyleBuild b = p1.scheduleBuild2(0).get();
            r.assertBuildStatus(Result.FAILURE, b);
            assertNotEquals(testingDisplayName, b.getDisplayName());
        }
        
        // Approve classpath.
        {
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().approveClasspath(pcp.getHash(), pcp.getPath());
            }
        }
        
        // Success as approved.
        {
            FreeStyleBuild b = p1.scheduleBuild2(0).get();
            r.assertBuildStatusSuccess(b);
            assertEquals(testingDisplayName, b.getDisplayName());
        }
        
        File tmpDir2 = tmpFolderRule.newFolder();
        
        for (File jarfile: getAllJarFiles()) {
            Expand e = new Expand();
            e.setSrc(jarfile);
            e.setDest(tmpDir2);
            e.execute();
        }
        
        // touch all files.
        {
            DirectoryScanner ds = new DirectoryScanner();
            ds.setBasedir(tmpDir2);
            ds.setIncludes(new String[]{ "**" });
            ds.scan();
            
            for (String relpath: ds.getIncludedFiles()) {
                Touch t = new Touch();
                t.setFile(new File(tmpDir2, relpath));
                t.execute();
            }
        }
        
        List<ClasspathEntry> classpathList2 = new ArrayList<ClasspathEntry>();
        classpathList2.add(new ClasspathEntry(tmpDir2.getAbsolutePath()));
        
        FreeStyleProject p2 = r.createFreeStyleProject();
        p2.getPublishersList().add(new TestGroovyRecorder(new SecureGroovyScript(
                String.format(
                        "import org.jenkinsci.plugins.scriptsecurity.testjar.BuildUtil;"
                        + "BuildUtil.setDisplayNameWhitelisted(build, \"%s\");"
                        + "\"\"", testingDisplayName),
                true,
                classpathList2
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
        GlobalMatrixAuthorizationStrategy gmas = new GlobalMatrixAuthorizationStrategy();
        gmas.add(Jenkins.READ, "devel");
        gmas.add(Jenkins.READ, "approver");
        gmas.add(Jenkins.RUN_SCRIPTS, "approver");
        for (Permission p : Item.PERMISSIONS.getPermissions()) {
            gmas.add(p, "devel");
            gmas.add(p, "approver");
        }
        r.jenkins.setAuthorizationStrategy(gmas);
        
        JenkinsRule.WebClient wcDevel = r.createWebClient();
        wcDevel.login("devel");
        
        JenkinsRule.WebClient wcApprover = r.createWebClient();
        wcApprover.login("approver");
        
        
        List<ClasspathEntry> classpathList = new ArrayList<ClasspathEntry>();
        
        for (File jarfile: getAllJarFiles()) {
            classpathList.add(new ClasspathEntry(jarfile.getAbsolutePath()));
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
                classpathList
        )));
        
        // Deny classpath.
        {
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().denyClasspath(pcp.getHash(), pcp.getPath());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspaths().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspaths().size());
        }
        
        // If configured by a user with RUN_SCRIPTS, the classpath is automatically approved
        {
            r.submit(wcApprover.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspath> acps = ScriptApproval.get().getApprovedClasspaths();
            assertNotEquals(0, acps.size());
            
            for(ScriptApproval.ApprovedClasspath acp: acps) {
                ScriptApproval.get().denyApprovedClasspath(acp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspaths().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspaths().size());
        }
        
        // If configured by a user without RUN_SCRIPTS, approval is requested
        {
            r.submit(wcDevel.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspath> acps = ScriptApproval.get().getApprovedClasspaths();
            assertEquals(0, acps.size());
            
            // don't remove pending classpaths.
        }
        
        // If configured by a user with RUN_SCRIPTS, the classpath is automatically approved, and removed from approval request.
        {
            assertNotEquals(0, ScriptApproval.get().getPendingClasspaths().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspaths().size());
            
            r.submit(wcApprover.getPage(p, "configure").getFormByName("config"));
            
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspath> acps = ScriptApproval.get().getApprovedClasspaths();
            assertNotEquals(0, acps.size());
            
            for(ScriptApproval.ApprovedClasspath acp: acps) {
                ScriptApproval.get().denyApprovedClasspath(acp.getHash());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspaths().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspaths().size());
        }
        
        // If run with SYSTEM user, an approval is requested.
        {
            r.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0).get());
            
            List<ScriptApproval.PendingClasspath> pcps = ScriptApproval.get().getPendingClasspaths();
            assertNotEquals(0, pcps.size());
            List<ScriptApproval.ApprovedClasspath> acps = ScriptApproval.get().getApprovedClasspaths();
            assertEquals(0, acps.size());
            
            for(ScriptApproval.PendingClasspath pcp: pcps) {
                ScriptApproval.get().denyClasspath(pcp.getHash(), pcp.getPath());
            }
            
            assertEquals(0, ScriptApproval.get().getPendingClasspaths().size());
            assertEquals(0, ScriptApproval.get().getApprovedClasspaths().size());
        }
    }
}
