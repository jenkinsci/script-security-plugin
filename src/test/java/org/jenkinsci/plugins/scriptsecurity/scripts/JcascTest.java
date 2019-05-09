package org.jenkinsci.plugins.scriptsecurity.scripts;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;

import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JcascTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("smoke-test-empty.yaml")
    public void smokeTestEmpty() throws Exception {
        String[] approved = ScriptApproval.get().getApprovedSignatures();
        assertTrue(approved.length == 0);
    }

    @Test
    @ConfiguredWithCode("smoke-test-entry.yaml")
    public void smokeTestEntry() throws Exception {
        String[] approved = ScriptApproval.get().getApprovedSignatures();
        assertTrue(approved.length == 1);
        assertEquals(approved[0], "method java.net.URI getHost");
    }
}
