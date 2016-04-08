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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import javax.annotation.CheckForNull;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Represents background information about who requested that a script or signature be approved and for what purpose.
 * When created from a thread that generally carries authentication, such as within a {@link DataBoundConstructor}, be sure to use {@link #withCurrentUser}.
 * Also use {@link #withItem} or {@link #withKey} or {@link #withItemAsKey} whenever possible.
 */
public final class ApprovalContext {

    private final @CheckForNull String user;
    private final @CheckForNull String item;
    private final @CheckForNull String key;

    private ApprovalContext(@CheckForNull String user, @CheckForNull String item, @CheckForNull String key) {
        this.user = user;
        this.item = item;
        this.key = key;
    }

    /**
     * Creates a new context with no information.
     */
    public static ApprovalContext create() {
        return new ApprovalContext(null, null, null);

    }

    /**
     * Creates a context with a specified user ID.
     * ({@link ACL#SYSTEM} is automatically ignored.)
     */
    public ApprovalContext withUser(@CheckForNull String user) {
        return new ApprovalContext(ACL.SYSTEM.getName().equals(user) ? null : user, item, key);
    }

    /**
     * Creates a context with the user associated with the current thread.
     * ({@link ACL#SYSTEM} is automatically ignored, but the user might be {@link Jenkins#ANONYMOUS}.)
     */
    public ApprovalContext withCurrentUser() {
        User u = User.current();
        return withUser(u != null ? u.getId() : Jenkins.ANONYMOUS.getName());
    }

    /**
     * Gets the associated {@linkplain User#getId user ID}, if any.
     */
    public @CheckForNull String getUser() {
        return user;
    }

    /**
     * Associates an item with this approval, used only for display purposes.
     */
    public ApprovalContext withItem(@CheckForNull Item item) {
        return item != null ? new ApprovalContext(user, item.getFullName(), key) : this;
    }

    /**
     * Gets any associated item which should be displayed to an administrator.
     */
    // TODO: To remove, use `getActiveInstance` 1.590+ and back to `getInstance` on 1.653+
    @SuppressFBWarnings(value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", justification = "https://github.com/jenkinsci/jenkins/pull/2094")
    public @CheckForNull Item getItem() {
        // TODO if getItemByFullName == null, we should removal the approval
        return item != null ? Jenkins.getInstance().getItemByFullName(item) : null;
    }

    /**
     * Associates a unique key with this approval.
     * If not null, any previous approval of the same kind with the same key will be canceled and replaced by this one.
     * Only considered for {@linkplain ScriptApproval#configuring whole-script approvals}, not {@linkplain ScriptApproval#accessRejected signature approvals} which are generic.
     */
    public ApprovalContext withKey(@CheckForNull String key) {
        return key != null ? new ApprovalContext(user, item, key) : this;
    }

    /**
     * Gets the unique key, if any.
     */
    public @CheckForNull String getKey() {
        return key;
    }

    /**
     * Associates an item with this approval for display, as well as setting a unique key
     * based on the {@link Item#getFullName} which would cancel any previous approvals for the same item.
     * Note that this only makes sense in cases where it is guaranteed that at most one approvable script
     * is configured on a given item, so do not use this with (for example) build steps.
     */
    public ApprovalContext withItemAsKey(@CheckForNull Item item) {
        if (item == null) {
            return this;
        }
        String n = item.getFullName();
        return new ApprovalContext(user, n, n);
    }

}
