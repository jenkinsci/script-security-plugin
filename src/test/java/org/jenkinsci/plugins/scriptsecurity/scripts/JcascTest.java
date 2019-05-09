package org.jenkinsci.plugins.scriptsecurity.scripts;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;

import io.jenkins.plugins.casc.misc.Util;
import io.jenkins.plugins.casc.model.CNode;
import org.junit.ClassRule;
import org.junit.Test;

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
    }

    @Test
    public void smokeTestExport() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = Util.getUnclassifiedRoot(context).get("scriptApproval");
        String exported = Util.toYamlString(yourAttribute);
        String expected = Util.toStringFromYamlFile(this, "smoke_test_expected.yaml");
        assertEquals(exported, expected);
    }
}
