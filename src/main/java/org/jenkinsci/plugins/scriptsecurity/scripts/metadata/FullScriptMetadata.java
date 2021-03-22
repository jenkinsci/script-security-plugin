/*
 * The MIT License
 *
 * Copyright (c) 2020, CloudBees, Inc.
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
package org.jenkinsci.plugins.scriptsecurity.scripts.metadata;

import org.jenkinsci.plugins.scriptsecurity.scripts.ApprovalContext;
import org.jenkinsci.plugins.scriptsecurity.scripts.Language;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.LanguageHelper;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;

@Restricted(NoExternalUse.class)
public class FullScriptMetadata {
    
    public static final FullScriptMetadata EMPTY = new FullScriptMetadata(true);

    /**
     * In characters
     */
    private int scriptLength = -1;
    private String languageName;
    
    private int usageCount = 0;
    private long lastTimeUsed = -1;

    private long lastApprovalTime = -1;
    private boolean wasPreapproved;

    /**
     * Only used for the cases where the metadata is missing (legacy or disabled)
     */
    private boolean empty = false;

    /**
     * When the approver authentication was passed in the context.
     * Not necessarily useful for common usage but the difference with {@link #lastApprovalTime} could be valuable for deeper investigation.
     */
    private long lastKnownApprovalTime = -1;
    private String lastKnownApproverLogin;

    private ApprovalContext lastContext;
    private HashSet<ApprovalContext> contextList = new LinkedHashSet<>();

    public FullScriptMetadata() {
    }

    private FullScriptMetadata(boolean empty) {
        this.empty = true;
    }

    /**
     * Called during the configuration of a script
     */
    public void notifyApprovalDuringConfiguring(@Nonnull String script, @Nonnull Language language, @Nonnull ApprovalContext context) {
        this.updateScriptAndLanguage(script, language.getName());

        this.updateContext(context);

        long now = new Date().getTime();
        this.lastApprovalTime = now;

        String user = context.getUser();
        if (user != null) {
            this.lastKnownApproverLogin = user;
            this.lastKnownApprovalTime = now;
        }
        // as it's approved during the configuration it means that was done by an admin
        this.wasPreapproved = true;
    }

    /**
     * Called when someone/something uses the approved script
     */
    public void notifyUsage(@Nonnull String script, @Nonnull Language language) {
        this.usageCount++;
        this.lastTimeUsed = new Date().getTime();

        this.updateScriptAndLanguage(script, language.getName());
    }

    /**
     * Called when a plugin decides to preapprove a script.
     * It's not necessarily a reaction to a user interaction.
     */
    public void notifyPreapproveSingle(@Nonnull String script, @Nonnull Language language, @CheckForNull String user) {
        long now = new Date().getTime();
        this.lastApprovalTime = now;

        this.updateScriptAndLanguage(script, language.getName());

        if (user != null) {
            this.lastKnownApproverLogin = user;
            this.lastKnownApprovalTime = now;
        }

        this.wasPreapproved = true;
    }

    /**
     * Called when a plugin decides to preapprove a script.
     * It's not necessarily a reaction to a user interaction.
     *
     * Expected to come only from test code, not production code.
     */
    public void notifyPreapproveAll(@Nonnull ScriptApproval.PendingScript pendingScript, @CheckForNull String approverLogin) {
        long now = new Date().getTime();
        this.lastApprovalTime = now;

        this.updateScriptAndLanguage(pendingScript.script, pendingScript.getLanguageName());

        ApprovalContext context = pendingScript.getContext();
        this.updateContext(context);

        if (approverLogin != null) {
            this.lastKnownApproverLogin = approverLogin;
            this.lastKnownApprovalTime = now;
        }

        this.wasPreapproved = true;
    }

    /**
     * Called when a script was approved from the ScriptSecurity page
     */
    public void notifyApproval(@CheckForNull ScriptApproval.PendingScript pendingScript, @CheckForNull String approverLogin) {
        long now = new Date().getTime();
        if (pendingScript != null) {
            this.updateScriptAndLanguage(pendingScript.script, pendingScript.getLanguageName());

            ApprovalContext context = pendingScript.getContext();
            this.updateContext(context);

            if (approverLogin != null) {
                this.lastKnownApproverLogin = approverLogin;
                this.lastKnownApprovalTime = now;
            }
        }
        this.lastApprovalTime = now;
    }

    private void updateScriptAndLanguage(@Nonnull String script, @Nonnull String languageName) {
        this.scriptLength = script.length();
        this.languageName = languageName;
    }

    private void updateContext(@Nonnull ApprovalContext context) {
        this.contextList.add(context);
        this.lastContext = context;
    }

    public boolean isEmpty() {
        return empty;
    }

    public int getUsageCount() {
        return usageCount;
    }

    public @CheckForNull Date getLastTimeUsedDate() {
        if (lastTimeUsed == -1) {
            return null;
        }
        return new Date(lastTimeUsed);
    }

    public long getLastTimeUsed() {
        return lastTimeUsed;
    }

    public boolean isWasPreapproved() {
        return wasPreapproved;
    }

    public @CheckForNull Date getLastApprovalTimeDate() {
        if (lastApprovalTime == -1) {
            return null;
        }
        return new Date(lastApprovalTime);
    }

    public long getLastApprovalTime() {
        return lastApprovalTime;
    }

    public @CheckForNull String getLastKnownApproverLogin() {
        return lastKnownApproverLogin;
    }

    public @CheckForNull Language getLanguage() {
        if (languageName == null) {
            return null;
        }
        return LanguageHelper.getLanguageFromName(languageName);
    }

    public @CheckForNull ApprovalContext getLastContext() {
        return lastContext;
    }

    public int getScriptLength() {
        return scriptLength;
    }
}
