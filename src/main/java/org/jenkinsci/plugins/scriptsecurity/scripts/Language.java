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

import hudson.ExtensionPoint;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A language for which we can request {@link ScriptApproval}.
 */
public abstract class Language implements ExtensionPoint {

    /**
     * Unique, permanent, internal identifier of this language.
     * @return a short unlocalized identifier, such as might be used for a filename extension
     */
    public abstract @NonNull String getName();

    /**
     * Display name of the language for use in the UI.
     * @return a localized name
     */
    public abstract @NonNull String getDisplayName();

    /**
     * A CodeMirror mode string, for purposes of displaying scripts in HTML.
     * @return a mode such as {@code clike}, or null
     */
    public @CheckForNull String getCodeMirrorMode() {
        return null;
    }

    // TODO hooks for configuring/using/checking, as needed

}
