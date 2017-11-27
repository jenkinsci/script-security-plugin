/*
 * The MIT License
 *
 * Copyright 2017 CloudBees, Inc.
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

package org.jenkinsci.plugins.scriptsecurity.scripts.languages;

import hudson.Extension;
import hudson.ExtensionList;
import hudson.Util;
import org.jenkinsci.plugins.scriptsecurity.scripts.Language;

/**
 * Language for launched processes, as per {@link Util#tokenize(String)} and {@link ProcessBuilder}.
 * Typically the launch is on the master so arbitrary content could be dangerous.
 */
@Extension
public class SystemCommandLanguage extends Language {

    public static Language get() {
        return ExtensionList.lookup(Language.class).get(SystemCommandLanguage.class);
    }

    @Override
    public String getName() {
        return "system-command";
    }

    @Override
    public String getDisplayName() {
        return "System Commands";
    }

}
