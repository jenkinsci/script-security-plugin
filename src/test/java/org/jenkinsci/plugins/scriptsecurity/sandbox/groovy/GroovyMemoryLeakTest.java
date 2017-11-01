package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import groovy.lang.MetaClass;
import hudson.model.FreeStyleProject;
import org.codehaus.groovy.reflection.ClassInfo;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.plugins.groovypostbuild.GroovyPostbuildRecorder;
import org.jvnet.hudson.test.BuildWatcher;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.MemoryAssert;

import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.junit.Assert.assertFalse;

/**
 * @author Sam Van Oort
 */
public class GroovyMemoryLeakTest {
    @ClassRule
    public static BuildWatcher buildWatcher = new BuildWatcher();
    @Rule
    public JenkinsRule r = new JenkinsRule();
    @Rule public LoggerRule logger = new LoggerRule().record(SecureGroovyScript.class, Level.FINER);

    @After
    public void clearLoaders() {
        LOADERS.clear();
    }
    private static final List<WeakReference<ClassLoader>> LOADERS = new ArrayList<>();

    public static void register(Object o) {
        ClassLoader loader = o.getClass().getClassLoader();
        System.err.println("registering " + o + " from " + loader);
        LOADERS.add(new WeakReference<>(loader));
    }

    @Test
    public void loaderReleased() throws Exception {
        FreeStyleProject p = r.jenkins.createProject(FreeStyleProject.class, "p");
        p.addPublisher(new GroovyPostbuildRecorder(
                new SecureGroovyScript(GroovyMemoryLeakTest.class.getName()+".register(this)", false, null),
                2, false
        ));
        r.buildAndAssertSuccess(p);

        assertFalse(LOADERS.isEmpty());
        { // TODO it seems that the call to CpsFlowExecutionMemoryTest.register(Object) on a Script1 parameter creates a MetaMethodIndex.Entry.cachedStaticMethod.
            // In other words any call to a foundational API might leak classes. Why does Groovy need to do this?
            // Unclear whether this is a problem in a realistic environment; for the moment, suppressing it so the test can run with no SoftReference.
            MetaClass metaClass = ClassInfo.getClassInfo(GroovyMemoryLeakTest.class).getMetaClass();
            Method clearInvocationCaches = metaClass.getClass().getDeclaredMethod("clearInvocationCaches");
            clearInvocationCaches.setAccessible(true);
            clearInvocationCaches.invoke(metaClass);
        }
        for (WeakReference<ClassLoader> loaderRef : LOADERS) {
            MemoryAssert.assertGC(loaderRef, false);
        }
    }
}
