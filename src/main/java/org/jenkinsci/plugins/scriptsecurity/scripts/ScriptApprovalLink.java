/*
 * The MIT License
 *
 * Copyright 2014 CloudBees, Inc.
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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.Permission;
import jenkins.management.Badge;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class) // implementation
@Extension public final class ScriptApprovalLink extends ManagementLink {

    @Override public String getIconFileName() {
        if (ScriptApproval.get().isEmpty()) {
            return null;
        }
        return "symbol-edit-note";
    }

    @Override public String getUrlName() {
        return ScriptApproval.get().getUrlName();
    }

    @Override public String getDisplayName() {
        return "In-process Script Approval";
    }

    @Override public String getDescription() {
        String message = "Allows a Jenkins administrator to review proposed scripts (written e.g. in Groovy) which run inside the Jenkins process and so could bypass security restrictions.";
        int outstanding = ScriptApproval.get().getPendingScripts().size();
        if (outstanding > 0) {
            // TODO consider using <span style="color:red; font-weight:bold"> like Manage Plugins does (but better for this to be defined in Jenkins CSS)
            message += " <strong>" + outstanding + " scripts pending approval.</strong>";
        }
        outstanding = ScriptApproval.get().getPendingSignatures().size();
        if (outstanding > 0) {
            message += " <strong>" + outstanding + " signatures pending approval.</strong>";
        }
        outstanding = ScriptApproval.get().getPendingClasspathEntries().size();
        if (outstanding > 0) {
            message += " <strong>" + outstanding + " classpath entries pending approval.</strong>";
        }
        int dangerous = ScriptApproval.get().getDangerousApprovedSignatures().length;
        if (dangerous > 0) {
            message += " <strong><font color='red'>" + dangerous + " dangerous signatures</font> previously approved which ought not have been.</strong>";
        }
        return message;
    }

    @NonNull
    @Override public Permission getRequiredPermission() {
        return Jenkins.ADMINISTER;
    }

    @NonNull
    @Override
    public Category getCategory() {
        return Category.SECURITY;
    }

    @Override
    public Badge getBadge() {
        int pendingScripts = ScriptApproval.get().getPendingScripts().size();
        int pendingSignatures = ScriptApproval.get().getPendingSignatures().size();
        int pendingClasspathEntries = ScriptApproval.get().getPendingClasspathEntries().size();
        int dangerous = ScriptApproval.get().getDangerousApprovedSignatures().length;
        int total = 0;
        StringBuilder toolTip = new StringBuilder();
        if (pendingScripts > 0) {
            total += pendingScripts;
            toolTip.append(Messages.ScriptApprovalLink_outstandingScript(pendingScripts));
        }
        if (pendingSignatures > 0) {
            if (total > 0) {
                toolTip.append("\n");
            }
            toolTip.append(Messages.ScriptApprovalLink_outstandingSignature(pendingSignatures));
            total += pendingSignatures;
        }
        if (pendingClasspathEntries > 0) {
            if (total > 0) {
                toolTip.append("\n");
            }
            toolTip.append(Messages.ScriptApprovalLink_outstandingClasspath(pendingClasspathEntries));
            total += pendingClasspathEntries;
        }
        if (total > 0 || dangerous > 0) {
            StringBuilder text = new StringBuilder();
            if (total > 0) {
                text.append(total);
            }
            if (dangerous > 0) {
                if (total > 0) {
                    toolTip.append("\n");
                    text.append("/");
                }
                text.append(dangerous);
                toolTip.append(Messages.ScriptApprovalLink_dangerous(dangerous));
            }
            Badge.Severity severity = dangerous > 0 ? Badge.Severity.DANGER : Badge.Severity.WARNING;
            return new Badge(text.toString(), toolTip.toString(), severity);
        }

        return null;
    }
}
