/*
 * The MIT License
 * 
 * Copyright (c) 2014 IKEDA Yasuyuki
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

package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import java.io.File;

import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

/**
 *
 */
public class AdditionalClasspath extends AbstractDescribableImpl<AdditionalClasspath> {
    private final String path;
    
    @DataBoundConstructor
    public AdditionalClasspath(String path) {
        this.path = path;
    }
    
    public String getPath() {
        return path;
    }
    
    public File getClasspath() {
        return new File(getPath());
    }
    
    @Override
    public String toString() {
        return String.format("Classpath: %s", getPath());
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AdditionalClasspath)) {
            return false;
        }
        
        if (getPath() == null) {
            return ((AdditionalClasspath)obj).getPath() == null;
        }
        
        return getPath().equals(((AdditionalClasspath)obj).getPath());
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<AdditionalClasspath> {
        @Override
        public String getDisplayName() {
            // TODO
            return "classpath";
        }
    }
}
