/*
 * The MIT License
 *
 * Copyright 2024 CloudBees, Inc.
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

import java.io.File;
import jenkins.RestartRequiredException;
import org.apache.commons.io.FileUtils;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;

class ScriptApprovalLoadingTest {

    @RegisterExtension
    private final RealJenkinsExtension extension = new RealJenkinsExtension();

    @Test
    void dynamicLoading() throws Throwable {
        extension.then(ScriptApprovalLoadingTest::_dynamicLoading1);
        extension.then(ScriptApprovalLoadingTest::_dynamicLoading2);
    }

    private static void _dynamicLoading1(JenkinsRule r) throws Throwable {
        File plugin = new File(r.jenkins.root, "plugins/script-security.jpl");
        FileUtils.copyFile(plugin, new File(plugin + ".bak"));
        r.jenkins.pluginManager.getPlugin("script-security").doDoUninstall();
    }

    private static void _dynamicLoading2(JenkinsRule r) throws Throwable {
        File plugin = new File(r.jenkins.root, "plugins/script-security.jpl");
        FileUtils.copyFile(new File(plugin + ".bak"), plugin);
        try {
            r.jenkins.pluginManager.dynamicLoad(plugin);
        } catch (RestartRequiredException x) {
            assumeTrue(false, "perhaps running in PCT, where this cannot be tested: " + x);
        }
        ScriptApproval sa = ScriptApproval.get();
        sa.approveSignature("method java.lang.Object wait");
        assertThat(sa.getApprovedSignatures(), arrayContaining("method java.lang.Object wait"));
    }
}
