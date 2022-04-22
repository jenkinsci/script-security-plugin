package org.jenkinsci.plugins.scriptsecurity.scripts;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;

import io.jenkins.plugins.casc.model.CNode;
import org.junit.ClassRule;
import org.junit.Test;

import static io.jenkins.plugins.casc.misc.Util.getSecurityRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JcascTest {

    @ClassRule
    @ConfiguredWithCode("smoke_test.yaml")
    public static JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    public void smokeTestEntry() throws Exception {
        String[] approved = ScriptApproval.get().getApprovedSignatures();
        assertTrue(approved.length == 1);
        assertEquals(approved[0], "method java.net.URI getHost");
        String[] approvedScriptHashes = ScriptApproval.get().getApprovedScriptHashes();
        assertTrue(approvedScriptHashes.length == 1);
        assertEquals(approvedScriptHashes[0], "fccae58c5762bdd15daca97318e9d74333203106");
    }

    @Test
    public void smokeTestExport() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getSecurityRoot(context).get("scriptApproval");
        String exported = toYamlString(yourAttribute);
        String expected = toStringFromYamlFile(this, "smoke_test_expected.yaml");
        assertEquals(exported, expected);
    }
}
