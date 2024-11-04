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

import hudson.Functions;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlPage;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyString;
import static org.junit.Assert.*;

import org.jvnet.hudson.test.*;

public class ClasspathEntryTest {
    @Rule public TemporaryFolder rule = new TemporaryFolder();
    @Rule public JenkinsRule jr = new JenkinsRule();

    @Issue("SECURITY-3447")
    @Test
    public void testDoCheckPath() throws Exception {
        jr.jenkins.setSecurityRealm(jr.createDummySecurityRealm());
        jr.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().
                grant(Jenkins.ADMINISTER).everywhere().to("admin")
                .grant(Jenkins.READ).everywhere().to("dev"));
        Path path = Files.createTempDirectory("temp dir");
        try(JenkinsRule.WebClient webClient = jr.createWebClient()) {
            webClient.login("admin");
            final HtmlPage adminPage = webClient.goTo("descriptor/org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry/checkPath?value=" + path.toUri());
            final String adminContent = adminPage.asXml();
            assertThat(adminContent, containsString("Class directories are not allowed as classpath entries."));
        }
        try (JenkinsRule.WebClient devWebClient = jr.createWebClient()) {
            devWebClient.login("dev");
            final HtmlPage devPage = devWebClient.goTo("descriptor/org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry/checkPath?value=" + path.toUri());
            final String devContent = devPage.asNormalizedText();
            assertThat(devContent, emptyString());
        }
        Files.deleteIfExists(path);

    }

    @WithoutJenkins
    @Test public void pathURLConversion() throws Exception {
        if (!Functions.isWindows()) {
            assertRoundTrip("/tmp/x.jar", "file:/tmp/x.jar");
        } else {
            assertRoundTrip("C:\\tmp\\x.jar", "file:/C:/tmp/x.jar");
        }
        assertRoundTrip("jar:file:/tmp/x.jar!/subjar.jar", "jar:file:/tmp/x.jar!/subjar.jar");
    }

    private static void assertRoundTrip(String path, String url) throws Exception {
        assertEquals(path, ClasspathEntry.urlToPath(new URL(url)));
        assertEquals(url, ClasspathEntry.pathToURL(path).toString());
    }

    @WithoutJenkins
    @Test public void classDirDetected() throws Exception {
        final File tmpDir = rule.newFolder();
        assertTrue("Existing directory must be detected", ClasspathEntry.isClassDirectoryURL(tmpDir.toURI().toURL()));
        tmpDir.delete();
        final File notExisting = new File(tmpDir, "missing");
        final URL missing = tmpDir.toURI().toURL();
        assertFalse("Non-existing file is not considered class directory", ClasspathEntry.isClassDirectoryURL(missing));
        final URL oneDir = new URL(missing.toExternalForm() + "/");
        assertTrue("Non-existing file is considered class directory if ending in /", ClasspathEntry.isClassDirectoryURL(oneDir));
        assertTrue("Generic URLs ending in / are considered class directories", ClasspathEntry.isClassDirectoryURL(new URL("http://example.com/folder/")));
        assertFalse("Generic URLs ending in / are not considered class directories", ClasspathEntry.isClassDirectoryURL(new URL("http://example.com/file")));
    }

    @WithoutJenkins
    @Issue("JENKINS-37599")
    @Test public void pathToURL() throws Exception {
        ClasspathEntry ignore = new ClasspathEntry("http://nowhere.net/");
        ignore = new ClasspathEntry(rule.newFile("x.jar").getAbsolutePath());
        ignore = new ClasspathEntry(rule.newFolder().getAbsolutePath());

        assertThrows(MalformedURLException.class, () -> new ClasspathEntry(""));
        assertThrows(MalformedURLException.class, () -> new ClasspathEntry(" "));
        assertThrows(MalformedURLException.class, () -> new ClasspathEntry("relative"));
    }

}