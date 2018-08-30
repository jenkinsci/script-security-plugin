package org.jenkinsci.plugins.scriptsecurity.casc;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;

/**
 * @author <a href="mailto:ohad.david@gmail.com">Ohad David</a>
 */
public class ScriptApprovalConfiguratorTest {
    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testCascLoadFromYaml() throws Exception{
        String resource = getClass().getResource("ScriptApprovalConfiguratorTest.yml").toExternalForm();
        ConfigurationAsCode.get().configure(Arrays.asList(resource));
        final ScriptApproval scriptApproval = ScriptApproval.get();
        String[] signatures = scriptApproval.getApprovedSignatures();
        Assert.assertArrayEquals(signatures, new String[]{
                "method java.net.URI getHost",
                "method java.net.URI getPort",
                "new java.net.URI java.lang.String"
        });
    }
}