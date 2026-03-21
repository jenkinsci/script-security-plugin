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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Base class for approvable entities.
 */
abstract class Approvable<T extends Approvable<T>> {
    Approvable() {
    }

    @SuppressWarnings("unchecked")
    final T self() {
        return (T) this;
    }

    abstract boolean findPending();

    abstract boolean findApproved();

    abstract T use() throws Exception;

    abstract boolean canUse() throws Exception;

    final T assertCannotUse() throws Exception {
        if (canUse()) {
            fail(this + "should have been rejected");
        }
        return self();
    }

    final T assertPending() {
        assertTrue(findPending(), this + " should be pending");
        assertFalse(findApproved(), this + " shouldn't be approved");
        return self();
    }

    final T assertApproved() {
        assertFalse(findPending(), this + " shouldn't be pending");
        assertTrue(findApproved(), this + " should be approved");
        return self();
    }

    final T assertDeleted() {
        assertFalse(findPending(), this + " shouldn't be pending");
        assertFalse(findApproved(), this + " shouldn't be approved");
        return self();
    }

    abstract T approve() throws Exception;

    abstract T deny() throws Exception;

    /** Returns whether the approvable supports deleting approved instances. */
    boolean canDelete() {
        return false;
    }

    /** If deletion is supported, it is implemented here. */
    T delete() throws Exception {
        throw new UnsupportedOperationException();
    }

    abstract Manager.Element<T> pending(Manager manager);

    abstract Manager.Element<T> approved(Manager manager);

    abstract T assertDeleted(Manager manager);


}
