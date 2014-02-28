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

package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

import hudson.Extension;
import java.lang.reflect.AccessibleObject;
import javax.annotation.CheckForNull;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Whitelists anything marked with {@link Whitelisted}.
 */
@Restricted(NoExternalUse.class)
@Extension public final class AnnotatedWhitelist extends AclAwareWhitelist {

    public AnnotatedWhitelist() {
        super(new Impl(false), new Impl(true));
    }

    private static final class Impl extends Whitelist {

        private final boolean restricted;

        Impl(boolean restricted) {
            this.restricted = restricted;
        }

        // TODO would be more efficient to preindex annotations

        private boolean allowed(@CheckForNull AccessibleObject o) {
            if (o == null) {
                return false;
            }
            Whitelisted ann = o.getAnnotation(Whitelisted.class);
            if (ann == null) {
                return false;
            }
            return ann.restricted() == restricted;
        }

        @Override public boolean permitsMethod(Object receiver, String method, Object[] args) {
            return allowed(StaticWhitelist.method(receiver, method, args));
        }

        @Override public boolean permitsNew(Class<?> receiver, Object[] args) {
            return allowed(StaticWhitelist.constructor(receiver, args));
        }

        @Override public boolean permitsStaticMethod(Class<?> receiver, String method, Object[] args) {
            return false; // TODO implement
        }

        @Override public boolean permitsFieldGet(Object receiver, String field) {
            return false; // TODO implement
        }

        @Override public boolean permitsFieldSet(Object receiver, String field, Object value) {
            return false; // TODO implement
        }

    }

}
