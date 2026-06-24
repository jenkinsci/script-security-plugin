package org.jenkinsci.plugins.scriptsecurity.scripts;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;

import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import org.junit.jupiter.api.Test;

import org.jvnet.hudson.test.LogRecorder;

import java.util.logging.Level;

import static io.jenkins.plugins.casc.misc.Util.getSecurityRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkinsConfiguredWithCode
class JcascTest {

    private final LogRecorder logger = new LogRecorder().record(ScriptApproval.class.getName(), Level.WARNING)
            .capture(100);

    @Test
    @ConfiguredWithCode("smoke_test.yaml")
    void smokeTestEntry(JenkinsConfiguredWithCodeRule j) {
        String[] approved = ScriptApproval.get().getApprovedSignatures();
        assertEquals(1, approved.length);
        assertEquals("method java.net.URI getHost", approved[0]);
        String[] approvedScriptHashes = ScriptApproval.get().getApprovedScriptHashes();
        assertEquals(1, approvedScriptHashes.length);
        assertEquals("fccae58c5762bdd15daca97318e9d74333203106", approvedScriptHashes[0]);
        assertThat(logger.getMessages(), containsInAnyOrder(
                containsString("Adding deprecated script hash " +
                        "that will be converted on next use: fccae58c5762bdd15daca97318e9d74333203106")));
        assertTrue(ScriptApproval.get().isForceSandbox());
    }

    @Test
    @ConfiguredWithCode("smoke_test.yaml")
    void smokeTestExport(JenkinsConfiguredWithCodeRule j) throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getSecurityRoot(context).get("scriptApproval");
        String exported = toYamlString(yourAttribute);
        String expected = toStringFromYamlFile(this, "smoke_test_expected.yaml");
        assertEquals(exported, expected);
    }
}
