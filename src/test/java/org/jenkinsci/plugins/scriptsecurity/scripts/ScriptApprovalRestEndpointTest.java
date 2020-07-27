package org.jenkinsci.plugins.scriptsecurity.scripts;

import hudson.PluginManager;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Jenkins.class, GroovyLanguage.class})
public class ScriptApprovalRestEndpointTest {
    @Mock
    private Jenkins jenkins;
    @Mock
    private PluginManager pluginManager;

    @Mock
    StaplerResponse resp;
    @Mock
    StaplerRequest request;


    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void setUp() throws Exception {
        mockStatic(Jenkins.class);
        when(Jenkins.getInstance()).thenReturn(jenkins);
        when(Jenkins.get()).thenReturn(jenkins);
        when(jenkins.getRootDir()).thenReturn(folder.getRoot());
        when(jenkins.getPluginManager()).thenReturn(pluginManager);
        mockStatic(GroovyLanguage.class);
        when(GroovyLanguage.get()).thenReturn(new GroovyLanguage());
    }

    @Test
    public void approvingScriptWithoutScriptPermissionFails() throws IOException, ServletException {
        when(jenkins.hasPermission(Mockito.any(Permission.class))).thenReturn(false);

        ScriptApproval scriptApproval = new ScriptApproval();
        HttpResponse httpResponse = scriptApproval.doApproveGroovy(request);

        httpResponse.generateResponse(null, resp, null);
        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void approvingScriptPersistsTheProvidedScript() throws IOException, ServletException {
        when(jenkins.hasPermission(Mockito.any(Permission.class))).thenReturn(true);
        when(request.getInputStream()).thenReturn(new Stream("println 'hello'"));
        String scriptHash = "20c13e13468ed85bc683546136489d8f75b87148"; // maybe we could make hash package protected for tests?

        ScriptApproval scriptApproval = new ScriptApproval();
        HttpResponse httpResponse = scriptApproval.doApproveGroovy(request);

        httpResponse.generateResponse(null, resp, null);
        verify(resp).setStatus(HttpServletResponse.SC_OK);
        assertThat(scriptApproval.isScriptHashApproved(scriptHash), is(true));

        // validate persistence
        assertThat(new ScriptApproval().isScriptHashApproved(scriptHash), is(true));
    }

    private static class Stream extends ServletInputStream {
        private final InputStream inputStream;

        Stream(String script) throws IOException {
            inputStream = IOUtils.toInputStream(script, "UTF-8");
        }

        @Override
        public int read() throws IOException {
            return inputStream.read();
        }

        @Override
        public boolean isFinished() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isReady() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException();
        }
    }

}
