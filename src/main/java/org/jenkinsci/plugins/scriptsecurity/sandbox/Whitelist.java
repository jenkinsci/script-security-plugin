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

package org.jenkinsci.plugins.scriptsecurity.sandbox;

import hudson.Extension;
import hudson.ExtensionPoint;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.GroovySandbox;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;

/**
 * Determines which methods and similar members which scripts may call.
 */
public abstract class Whitelist implements ExtensionPoint {

    /**
     * Checks whether a given virtual method may be invoked.
     * <p>Note that {@code method} should not be implementing or overriding a method in a supertype;
     * in such a case the caller must pass that supertype method instead.
     * In other words, call site selection is the responsibility of the caller (such as {@link GroovySandbox}), not the whitelist.
     * @param method a method defined in the JVM
     * @param receiver {@code this}, the receiver of the method call
     * @param args zero or more arguments
     * @return true to allow the method to be called, false to reject it
     */
    public abstract boolean permitsMethod(Method method, Object receiver, Object[] args);

    public abstract boolean permitsConstructor(Constructor<?> constructor, Object[] args);

    public abstract boolean permitsStaticMethod(Method method, Object[] args);

    public abstract boolean permitsFieldGet(Field field, Object receiver);

    public abstract boolean permitsFieldSet(Field field, Object receiver, Object value);

    // TODO add methods for static field get/set

    /**
     * Checks for all whitelists registered as {@link Extension}s and aggregates them.
     * @return an aggregated default list
     */
    public static synchronized Whitelist all() {
        if (all == null) {
            // TODO should check for dynamic changes in this list, e.g. from dynamically loaded plugins, and return a fresh aggregate
            all = new ProxyWhitelist(Jenkins.getInstance().getExtensionList(Whitelist.class));
        }
        return all;
    }
    private static Whitelist all;

}
