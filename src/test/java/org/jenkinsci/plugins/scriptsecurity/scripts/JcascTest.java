package org.jenkinsci.plugins.scriptsecurity.scripts;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;

import io.jenkins.plugins.casc.model.CNode;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.LoggerRule;

import java.util.logging.Level;

import static io.jenkins.plugins.casc.misc.Util.getSecurityRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;

public class JcascTest {

    @ClassRule(order = 1)
    public static LoggerRule logger = new LoggerRule().record(ScriptApproval.class.getName(), Level.WARNING)
            .capture(100);

    @ClassRule(order = 2)
    @ConfiguredWithCode("smoke_test.yaml")
    public static JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();



    @Test
    public void smokeTestEntry() throws Exception {
        String[] approved = ScriptApproval.get().getApprovedSignatures();
        assertEquals(1, approved.length);
        assertEquals(approved[0], "method java.net.URI getHost");
        String[] approvedScriptHashes = ScriptApproval.get().getApprovedScriptHashes();
        assertEquals(1, approvedScriptHashes.length);
        assertEquals(approvedScriptHashes[0], "fccae58c5762bdd15daca97318e9d74333203106");
        assertThat(logger.getMessages(), containsInAnyOrder(
                containsString("Adding deprecated script hash " +
                        "that will be converted on next use: fccae58c5762bdd15daca97318e9d74333203106")));
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
