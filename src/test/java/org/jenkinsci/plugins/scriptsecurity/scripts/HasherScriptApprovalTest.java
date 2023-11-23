package org.jenkinsci.plugins.scriptsecurity.scripts;

import org.hamcrest.Matcher;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsSessionRule;
import org.jvnet.hudson.test.LoggerRule;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HasherScriptApprovalTest {
    @Rule
    public JenkinsSessionRule session = new JenkinsSessionRule();
    @Rule
    public LoggerRule log = new LoggerRule();

    @Test
    @Issue("SECURITY-2564")
    public void hasherMatchesItsOwnHashes() throws Throwable {
        session.then(r -> {
            for (ScriptApproval.Hasher hasher : ScriptApproval.Hasher.values()) {
                assertTrue(hasher.pattern().matcher(hasher.hash("Hello World", "Text")).matches());
            }
        });
    }

    @Test
    @Issue("SECURITY-2564")
    public void warnsAndClearsDeprecatedScriptHashes() throws Throwable {
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            approval.approveScript(ScriptApproval.Hasher.SHA1.hash("Hello World", "Text"));
            approval.approveScript(ScriptApproval.Hasher.SHA1.hash("node { echo 'Hello World' }", "Groovy"));
            approval.approveScript(ScriptApproval.DEFAULT_HASHER.hash("have you tried it sometime?", "Text"));
        });
        log.record(ScriptApproval.class.getName(), Level.FINE).capture(10000);
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            assertEquals(2, approval.countDeprecatedApprovedScriptHashes());
            assertThat(log.getMessages(), hasItem(
                    containsString("There are 2 deprecated approved script hashes " +
                            "and 0 deprecated approved classpath hashes.")));
            approval.clearDeprecatedApprovedScripts();
            assertEquals(0, approval.countDeprecatedApprovedScriptHashes());
        });
    }

    @Test
    @Issue("SECURITY-2564")
    public void convertsScriptApprovalsOnUse() throws Throwable {
        final String script = "node { echo 'Hello World' }";
        final Matcher<Iterable<? extends String>> logMatcher = containsInRelativeOrder(
                containsString("A script is approved with an old hash algorithm. Converting now, "));
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            approval.approveScript(ScriptApproval.Hasher.SHA1.hash("Hello World", "Text"));
            approval.approveScript(ScriptApproval.Hasher.SHA1.hash(script, GroovyLanguage.get().getName()));
            approval.approveScript(ScriptApproval.DEFAULT_HASHER.hash("have you tried it sometime?", "Text"));
        });
        log.record(ScriptApproval.class.getName(), Level.FINE).capture(10000);
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            assertEquals(2, approval.countDeprecatedApprovedScriptHashes());
            approval.using(script, GroovyLanguage.get());
            assertEquals(1, approval.countDeprecatedApprovedScriptHashes());
            assertThat(log.getMessages(), logMatcher);
        });
        log.capture(10000);
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            assertEquals(1, approval.countDeprecatedApprovedScriptHashes());
            approval.using(script, GroovyLanguage.get());
            assertEquals(1, approval.countDeprecatedApprovedScriptHashes());
            assertThat(log.getMessages(), not(logMatcher));
        });
    }

    @Test
    @Issue("SECURITY-2564")
    public void testConvertApprovedClasspathEntries() throws Throwable {
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            addApprovedClasspathEntries(approval);
            assertEquals(2, approval.countDeprecatedApprovedClasspathHashes());
        });
        log.record(ScriptApproval.class.getName(), Level.FINE).capture(10000);
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            assertEquals(2, approval.countDeprecatedApprovedClasspathHashes());

            assertThat(log.getMessages(), hasItem(
                    containsString("There are 0 deprecated approved script hashes " +
                            "and 2 deprecated approved classpath hashes.")));

            approval.convertDeprecatedApprovedClasspathEntries();
            assertThat(log.getMessages(), containsInRelativeOrder(
                    containsString("Scheduling conversion of 2 deprecated approved classpathentry hashes."),
                    containsString("Background conversion task scheduled.")));
            try {
                while (approval.isConvertingDeprecatedApprovedClasspathEntries()) {
                    Thread.sleep(500);
                }
            } catch (InterruptedException ignored) {
            }
            assertEquals(0, approval.countDeprecatedApprovedClasspathHashes());
        });
    }

    @Test
    @Issue("SECURITY-2564")
    public void testClasspathEntriesConvertedOnUse() throws Throwable {
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            addApprovedClasspathEntries(approval);
            assertEquals(2, approval.countDeprecatedApprovedClasspathHashes());
        });
        log.record(ScriptApproval.class.getName(), Level.FINE).capture(10000);
        session.then(r -> {
            final ScriptApproval approval = ScriptApproval.get();
            assertEquals(2, approval.countDeprecatedApprovedClasspathHashes());
            URL url = getJar("org/apache/commons/lang3/StringUtils.class");
            approval.using(new ClasspathEntry(url.toString()));
            assertEquals(1, approval.countDeprecatedApprovedClasspathHashes());
            final Matcher<Iterable<? extends String>> logMatcher = containsInRelativeOrder(
                    containsString("A classpath is approved with an old hash algorithm. Converting now, "));
            assertThat(log.getMessages(), logMatcher);
            log.capture(1000);
            approval.using(new ClasspathEntry(url.toString())); //Using it again should not convert it again.
            assertThat(log.getMessages(), not(logMatcher));
            assertEquals(1, approval.countDeprecatedApprovedClasspathHashes());
        });
    }

    private void addApprovedClasspathEntries(final ScriptApproval approval) throws IOException {
        URL url = getJar("org/apache/commons/lang3/StringUtils.class");
        ScriptApproval.ApprovedClasspathEntry acp = new ScriptApproval.ApprovedClasspathEntry(
                ScriptApproval.Hasher.SHA1.hashClasspathEntry(url),
                url
        );
        approval.addApprovedClasspathEntry(acp);

        url = getJar("net/sf/json/JSON.class");
        acp = new ScriptApproval.ApprovedClasspathEntry(
                ScriptApproval.Hasher.SHA1.hashClasspathEntry(url),
                url
        );
        approval.addApprovedClasspathEntry(acp);
        approval.save();
    }

    @NonNull
    private URL getJar(final String resource) throws MalformedURLException {
        URL url = getClass().getClassLoader().getResource(resource);
        String path = url.getPath();
        path = path.substring(0, path.indexOf('!'));
        return new URL(path);
    }
}
