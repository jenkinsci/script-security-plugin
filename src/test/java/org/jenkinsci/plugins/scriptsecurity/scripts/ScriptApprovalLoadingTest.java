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
import org.apache.commons.io.FileUtils;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.RealJenkinsRule;

public final class ScriptApprovalLoadingTest {

    @Rule public final RealJenkinsRule rr = new RealJenkinsRule().prepareHomeLazily(true);

    @Test public void dynamicLoading() throws Throwable {
        File marker = new File(rr.getHome(), "plugins/script-security.jpl.disabled");
        FileUtils.createParentDirectories(marker);
        FileUtils.touch(marker);
        rr.then(ScriptApprovalLoadingTest::_dynamicLoading1);
        rr.then(ScriptApprovalLoadingTest::_dynamicLoading2);
    }

    private static void _dynamicLoading1(JenkinsRule r) throws Throwable {
        File plugin = new File(r.jenkins.root, "plugins/script-security.jpl");
        FileUtils.copyFile(plugin, new File(plugin + ".bak"));
        r.jenkins.pluginManager.getPlugin("script-security").doDoUninstall();
    }

    private static void _dynamicLoading2(JenkinsRule r) throws Throwable {
        File plugin = new File(r.jenkins.root, "plugins/script-security.jpl");
        FileUtils.copyFile(new File(plugin + ".bak"), plugin);
        r.jenkins.pluginManager.dynamicLoad(plugin);
        ScriptApproval sa = ScriptApproval.get();
        sa.approveSignature("method java.lang.Object wait");
        assertThat(sa.getApprovedSignatures(), arrayContaining("method java.lang.Object wait"));
    }

}
