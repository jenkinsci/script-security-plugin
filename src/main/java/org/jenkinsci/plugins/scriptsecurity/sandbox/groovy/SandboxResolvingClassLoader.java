package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import groovy.lang.GroovyShell;

/**
 * Makes sure that the class references to groovy-sandbox resolves to our own copy of
 * <tt>groovy-sandbox.jar</tt> instead of the random one picked up by the classloader
 * given to {@link GroovyShell} via the constructor.
 *
 * @see <a href="https://issues.jenkins-ci.org/browse/JENKINS-25348">JENKINS-25438</a>
 * @author Kohsuke Kawaguchi
 */
class SandboxResolvingClassLoader extends ClassLoader {
    public SandboxResolvingClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override
    protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.kohsuke.groovy.sandbox.")) {
            return this.getClass().getClassLoader().loadClass(name);
        } else {
            return super.loadClass(name, resolve);
        }
    }
}
