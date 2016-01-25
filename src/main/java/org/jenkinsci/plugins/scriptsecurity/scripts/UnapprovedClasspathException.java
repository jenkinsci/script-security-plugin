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

import java.net.URL;

/**
 * Exception thrown by {@link ScriptApproval#using(ClasspathEntry)}.
 */
public final class UnapprovedClasspathException extends SecurityException {

    private static final long serialVersionUID = -4774006715053263794L;
    private final URL url;
    private final String hash;

    UnapprovedClasspathException(URL url, String hash) {
        super(String.format("classpath entry %s (%s) not yet approved for use", url, hash));
        this.url = url;
        this.hash = hash;
    }

    public URL getURL() {
        return url;
    }
    
    /**
     * Gets a token which identifies the contents of the unapproved classpath entry.
     * @return the SHA-1 of the entry
     */
    public String getHash() {
        return hash;
    }

}
