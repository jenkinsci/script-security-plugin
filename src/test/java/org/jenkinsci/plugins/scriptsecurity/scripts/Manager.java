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

package org.jenkinsci.plugins.scriptsecurity.scripts;

import com.gargoylesoftware.htmlunit.ConfirmHandler;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Object representing the script approval page.
 */
final class Manager {
    private final JenkinsRule.WebClient wc;
    private final HtmlPage page;

    Manager(JenkinsRule rule) throws Exception {
        this.wc = rule.createWebClient();
        // click "OK" for all confirms.
        wc.setConfirmHandler(new ConfirmHandler() {
            public boolean handleConfirm(Page page, String message) {
                return true;
            }
        });
        this.page = wc.goTo(ScriptApproval.get().getUrlName());
    }

    private void clickAndWait(HtmlElement e) throws IOException {
        e.click();
        wc.waitForBackgroundJavaScript(10000);
    }

    Manager click(String id) throws IOException {
        clickAndWait(page.getElementById(id).getElementsByTagName("button").get(0));
        return this;
    }

    Manager notFound(Approvable<?> a, String id) {
        assertNull(String.format("%s : Element %s should not exist", a, id), page.getElementById(id));
        return this;
    }

    private DomElement assertFound(Approvable<?> a, String id) {
        DomElement dom = page.getElementById(id);
        assertNotNull(String.format("%s : Element %s should exist", this, id), dom);
        return dom;
    }

    <T extends Approvable<T>> Element<T> found(T entry, String id) {
        return new Element(entry, assertFound(entry, id));
    }

    final class Element<T extends Approvable<T>> {
        final T approvable;
        private final DomElement element;

        Element(T approvable, DomElement element) {
            this.approvable = approvable;
            this.element = element;
        }

        T click(String value) throws IOException {
            for (HtmlElement e : element.getElementsByTagName("button")) {
                if (e.hasAttribute("class") && value.equals(e.getAttribute("class"))) {
                    clickAndWait(e);
                    return approvable;
                }
            }
            throw new AssertionError(String.format("Unable to find button with class [%s] in element [%s]", value, approvable));
        }

        T approve() throws IOException {
            approvable.assertPending();
            return click("approve");
        }

        T deny() throws IOException {
            approvable.assertPending();
            return click("deny");
        }

        T delete() throws IOException {
            assertTrue(approvable + "must support deletion", approvable.canDelete());
            approvable.assertApproved();
            return click("delete");
        }
    }
}
