/*
 * The MIT License
 *
 * Copyright 2019 CloudBees, Inc.
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

import hudson.Extension;
import hudson.MarkupText;
import hudson.console.ConsoleAnnotationDescriptor;
import hudson.console.ConsoleAnnotator;
import hudson.console.ConsoleNote;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Offers a link to {@link ScriptApproval}.
 */
@Restricted(NoExternalUse.class)
public class ScriptApprovalNote extends ConsoleNote<Object> {

    private static final Logger LOGGER = Logger.getLogger(ScriptApprovalNote.class.getName());

    public static void print(TaskListener listener, RejectedAccessException x) {
        try {
            String text = Messages.ScriptApprovalNote_message();
            listener.getLogger().println(x.getMessage() + ". " + new ScriptApprovalNote(text.length()).encode() + text);
        } catch (IOException x2) {
            LOGGER.log(Level.WARNING, null, x2);
        }
    }

    private final int length;

    private ScriptApprovalNote(int length) {
        this.length = length;
    }

    @Override
    public ConsoleAnnotator<Object> annotate(Object context, MarkupText text, int charPos) {
        if (Jenkins.getInstance().hasPermission(Jenkins.RUN_SCRIPTS)) {
            String url = ScriptApproval.get().getUrlName();
            StaplerRequest req = Stapler.getCurrentRequest();
            if (req != null) {
                // if we are serving HTTP request, we want to use app relative URL
                url = req.getContextPath() + "/" + url;
            } else {
                // otherwise presumably this is rendered for e-mails and other non-HTTP stuff
                url = Jenkins.getInstance().getRootUrl() + url;
            }
            text.addMarkup(charPos, charPos + length, "<a href='" + url + "'>", "</a>");
        }
        return null;
    }

    
    @Symbol("scriptApprovalLink")
    @Extension public static class DescriptorImpl extends ConsoleAnnotationDescriptor {}

}
