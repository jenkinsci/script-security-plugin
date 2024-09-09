/*
 * The MIT License
 *
 * Copyright 2016 CloudBees, Inc.
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

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxInterceptorTest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.jvnet.hudson.test.Issue;

public class GenericWhitelistTest {
    
    @Rule public ErrorCollector errors = new ErrorCollector();

    @Test public void sanity() throws Exception {
        StaticWhitelistTest.sanity(StaticWhitelist.class.getResource("generic-whitelist"));
    }

    @Issue("SECURITY-538")
    @Test public void dynamicSubscript() throws Exception {
        String dangerous = Dangerous.class.getName();
        Whitelist wl = new ProxyWhitelist(new GenericWhitelist(), new AnnotatedWhitelist());
        // Control cases—explicit method call:
        SandboxInterceptorTest.assertRejected(wl, "staticMethod " + dangerous + " isSecured", dangerous + ".isSecured()", errors);
        SandboxInterceptorTest.assertRejected(wl, "staticMethod " + dangerous + " setSecured boolean", dangerous + ".setSecured(false)", errors);
        SandboxInterceptorTest.assertRejected(wl, "method " + dangerous + " getSecret", "new " + dangerous + "().getSecret()", errors);
        SandboxInterceptorTest.assertRejected(wl, "method " + dangerous + " setSecret java.lang.String", "new " + dangerous + "().setSecret('')", errors);
        // Control cases—statically resolvable property accesses:
        SandboxInterceptorTest.assertRejected(wl, "staticMethod " + dangerous + " isSecured", dangerous + ".secured", errors);
        SandboxInterceptorTest.assertRejected(wl, "staticMethod " + dangerous + " setSecured boolean", dangerous + ".secured = false", errors);
        SandboxInterceptorTest.assertRejected(wl, "method " + dangerous + " getSecret", "new " + dangerous + "().secret", errors);
        SandboxInterceptorTest.assertRejected(wl, "method " + dangerous + " setSecret java.lang.String", "new " + dangerous + "().secret = ''", errors);
        // Test cases—dynamically resolved property accesses:
        String getAt = "staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods getAt java.lang.Object java.lang.String";
        String putAt = "staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods putAt java.lang.Object java.lang.String java.lang.Object";
        SandboxInterceptorTest.assertRejected(wl, getAt, dangerous + "['secured']", errors);
        SandboxInterceptorTest.assertRejected(wl, putAt, dangerous + "['secured'] = false", errors);
        SandboxInterceptorTest.assertRejected(wl, getAt, "new " + dangerous + "()['secret']", errors);
        SandboxInterceptorTest.assertRejected(wl, putAt, "new " + dangerous + "()['secret'] = ''", errors);
        // Test cases via JsonOutput.
        SandboxInterceptorTest.assertRejected(wl, "staticMethod groovy.json.JsonOutput toJson java.lang.Object", "groovy.json.JsonOutput.toJson(new " + dangerous + "())", errors);
        // toJson(Closure) seems blocked anyway by lack of access to JsonDelegate.content, directly or via GroovyObject.setProperty
    }
    public static class Dangerous {
        @Whitelisted
        public Dangerous() {}
        public static boolean isSecured() {return true;}
        public static void setSecured(boolean secured) {}
        public String getSecret() {return null;}
        public void setSecret(String secret) {}
    }

}
