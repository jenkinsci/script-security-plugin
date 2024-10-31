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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.BallColor;
import hudson.model.Descriptor;
import hudson.model.PageDecorator;
import hudson.security.ACLContext;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.util.SystemProperties;

import gnu.crypto.hash.IMessageDigest;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.AclAwareWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.ProxyWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.GroovySandbox;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.Util;
import hudson.XmlFile;
import hudson.model.RootAction;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.XStream2;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import jenkins.model.Jenkins;
import net.sf.json.JSON;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.bind.JavaScriptMethod;
import org.kohsuke.stapler.verb.POST;

/**
 * Manages approved scripts.
 */
@Symbol("scriptApproval")
@Extension
public final class ScriptApproval extends GlobalConfiguration implements RootAction {

    /**
     * SECURITY-2450: Since 1172.v35f6a_0b_8207e, unmodified, unsandboxed scripts are no longer automatically approved
     * when administrators submit job configuration forms.
     * <p>
     *     This flag restores the previous behavior when set to {@code true}.
     * </p>
     *
     * @see <a href="https://github.com/jenkinsci/script-security-plugin/releases/tag/1172.v35f6a_0b_8207e">1172.v35f6a_0b_8207e changelog</a>
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "for script console")
    public static /* non-final */ boolean ADMIN_AUTO_APPROVAL_ENABLED =
            SystemProperties.getBoolean(ScriptApproval.class.getName() + ".ADMIN_AUTO_APPROVAL_ENABLED");

    /**
     * SECURITY-3103: Since 1265.va_fb_290b_4b_d34, administrators saving jobs (e.g., when copying existing jobs with
     * unapproved scripts) will no longer result in unapproved scripts in those configurations being approved.
     * <p>
     *     This flag restores the previous behavior when set to {@code true}.
     * </p>
     *
     * @see <a href="https://github.com/jenkinsci/script-security-plugin/releases/tag/1265.va_fb_290b_4b_d34">1265.va_fb_290b_4b_d34 changelog</a>
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "for script console")
    public static /* non-final */ boolean ALLOW_ADMIN_APPROVAL_ENABLED =
            SystemProperties.getBoolean(ScriptApproval.class.getName() + ".ALLOW_ADMIN_APPROVAL_ENABLED");

    private static final Logger LOG = Logger.getLogger(ScriptApproval.class.getName());

    private static final XStream2 XSTREAM2 = new XStream2();
    static {
        // Compatibility:
        XSTREAM2.alias("com.cloudbees.hudson.plugins.modeling.scripts.ScriptApproval", ScriptApproval.class);
        XSTREAM2.alias("com.cloudbees.hudson.plugins.modeling.scripts.ScriptApproval$PendingScript", PendingScript.class);
        XSTREAM2.alias("com.cloudbees.hudson.plugins.modeling.scripts.ScriptApproval$PendingSignature", PendingSignature.class);
        // Current:
        XSTREAM2.alias("scriptApproval", ScriptApproval.class);
        XSTREAM2.alias("approvedClasspathEntry", ApprovedClasspathEntry.class);
        XSTREAM2.alias("pendingScript", PendingScript.class);
        XSTREAM2.alias("pendingSignature", PendingSignature.class);
        XSTREAM2.alias("pendingClasspathEntry", PendingClasspathEntry.class);
    }

    @Override
    protected XmlFile getConfigFile() {
        return new XmlFile(XSTREAM2, new File(Jenkins.get().getRootDir(),getUrlName() + ".xml"));
    }

    @NonNull
    @Override
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    /** Gets the singleton instance. */
    public static @NonNull ScriptApproval get() {
        ScriptApproval instance = ExtensionList.lookup(RootAction.class).get(ScriptApproval.class);
        if (instance == null) {
            throw new IllegalStateException("maybe need to rebuild plugin?");
        }
        return instance;
    }

    /**
     * Approved classpath entry.
     * 
     * It is keyed only by the hash,
     * but additional information is provided for convenience.
     */
    @Restricted(NoExternalUse.class) // for use from Jelly and tests
    public static class ApprovedClasspathEntry implements Comparable<ApprovedClasspathEntry> {
        private final String hash;
        private final URL url;
        
        public ApprovedClasspathEntry(String hash, URL url) {
            this.hash = hash;
            this.url = url;
        }
        
        public String getHash() {
            return hash;
        }
        
        public URL getURL() {
            return url;
        }

        /**
         * Checks whether the entry would be considered a class directory.
         * @see ClasspathEntry#isClassDirectoryURL(URL)
         */
        boolean isClassDirectory() {
            return ClasspathEntry.isClassDirectoryURL(url);
        }


        @Override public int hashCode() {
            return hash.hashCode();
        }
        @Override public boolean equals(Object obj) {
            return obj instanceof ApprovedClasspathEntry && ((ApprovedClasspathEntry) obj).hash.equals(hash);
        }
        @Override public int compareTo(ApprovedClasspathEntry o) {
            return hash.compareTo(o.hash);
        }
    }

    enum Hasher {
        SHA512 {
            final Pattern shaPattern = Pattern.compile("SHA512:[a-fA-F0-9]{128}");
            @Override
            String prefix() {
                return "SHA512:";
            }

            @Override
            MessageDigest digest() throws NoSuchAlgorithmException {
                return MessageDigest.getInstance("SHA-512");
            }

            @Override
            Pattern pattern() {
                return shaPattern;
            }
        },
        @Deprecated
        SHA1 {
            final Pattern shaPattern = Pattern.compile("[a-fA-F0-9]{40}");
            @Override
            String prefix() {
                return "";
            }
            @Override
            MessageDigest digest() throws NoSuchAlgorithmException {
                return MessageDigest.getInstance("SHA-1");
            }

            @Override
            Pattern pattern() {
                return shaPattern;
            }
        };
        String hash(String script, String language) {
            try {
                MessageDigest digest = digest();
                digest.update(language.getBytes(StandardCharsets.UTF_8));
                digest.update((byte) ':');
                digest.update(script.getBytes(StandardCharsets.UTF_8));
                return prefix() + Util.toHexString(digest.digest());
            } catch (NoSuchAlgorithmException x) {
                throw new AssertionError(x);
            }
        }

        /**
         * Creates digest of JAR contents.
         * Package visibility to be used in tests.
         */
        String hashClasspathEntry(URL entry) throws IOException {
            try {
                MessageDigest digest = digest();
                try (InputStream is = entry.openStream(); BufferedInputStream bis = new BufferedInputStream(is); DigestInputStream input = new DigestInputStream(bis, digest)) {
                    byte[] buffer = new byte[1024];
                    while (input.read(buffer) != -1) {
                        // discard
                    }
                    return prefix() + Util.toHexString(digest.digest());
                }
            } catch (NoSuchAlgorithmException x) {
                throw new AssertionError(x);
            }
        }
        abstract String prefix();
        abstract MessageDigest digest() throws NoSuchAlgorithmException;
        abstract Pattern pattern();
    }

    static final Hasher DEFAULT_HASHER = Hasher.SHA512;

    private transient Thread convertDeprecatedApprovedClasspathEntriesThread = null;

    /** All scripts which are already approved, via {@link Hasher#hash(String, String)}. */
    private final TreeSet<String> approvedScriptHashes = new TreeSet<>();

    /** All sandbox signatures which are already whitelisted, in {@link StaticWhitelist} format. */
    private final TreeSet<String> approvedSignatures = new TreeSet<>();

    /** All sandbox signatures which are already whitelisted for ACL-only use, in {@link StaticWhitelist} format. */
    private /*final*/ TreeSet<String> aclApprovedSignatures;

    /** All external classpath entries allowed used for scripts. */
    private /*final*/ TreeSet<ApprovedClasspathEntry> approvedClasspathEntries;

    /** when this mode is enabled, the full logic for accepting/rejecting scripts will be hidden */
    private boolean forceSandbox;

    /* for test */ synchronized void addApprovedClasspathEntry(ApprovedClasspathEntry acp) {
        approvedClasspathEntries.add(acp);
    }

    public boolean isScriptApproved(@NonNull String script, @NonNull Language language) {
        for (Hasher hasher : Hasher.values()) { //Default Hasher should be first in the array
            String hash = hasher.hash(script, language.getName());
            if (this.isScriptHashApproved(hash)) {
                return true;
            }
        }
        return false;
    }

    static class ConversionCheckResult {
        final String oldHash;
        final String newHash;
        final boolean approved;
        final boolean converted;

        public ConversionCheckResult(final String oldHash, final String newHash, final boolean approved, final boolean converted) {
            this.oldHash = oldHash;
            this.newHash = newHash;
            this.approved = approved;
            this.converted = converted;
        }
    }

    @Restricted(NoExternalUse.class) @NonNull
    private synchronized ConversionCheckResult checkAndConvertApprovedScript(@NonNull String script, @NonNull Language language) {
        String hash = DEFAULT_HASHER.hash(script, language.getName());
        if (approvedScriptHashes.contains(hash)) {
            return new ConversionCheckResult(hash, hash, true, false);
        }
        for (Hasher hasher : Hasher.values()) {
            if (hasher != DEFAULT_HASHER) {
                String oldHash = hasher.hash(script, language.getName());
                if (approvedScriptHashes.contains(oldHash)) {
                    LOG.fine("A script is approved with an old hash algorithm. " +
                            "Converting now, this may cause performance issues until all old hashes has been converted or removed.");
                    approvedScriptHashes.remove(oldHash);
                    approvedScriptHashes.add(hash);
                    save();
                    return new ConversionCheckResult(oldHash, hash, true, true);
                }
            }
        }
        return new ConversionCheckResult(hash, hash, false, false);
    }

    @Restricted(NoExternalUse.class) @NonNull
    private synchronized ConversionCheckResult checkAndConvertApprovedClasspath(@NonNull URL url) throws IOException {
        String hash = DEFAULT_HASHER.hashClasspathEntry(url);
        ApprovedClasspathEntry acp = new ApprovedClasspathEntry(hash, url);
        if (approvedClasspathEntries.contains(acp)) {
            return new ConversionCheckResult(hash, hash, true, false);
        }
        for (Hasher hasher : Hasher.values()) {
            if (hasher != DEFAULT_HASHER) {
                String oldHash = hasher.hashClasspathEntry(url);
                ApprovedClasspathEntry oacp = new ApprovedClasspathEntry(oldHash, url);
                if (approvedClasspathEntries.contains(oacp)) {
                    LOG.fine("A classpath is approved with an old hash algorithm. " +
                            "Converting now, this may cause performance issues until all old hashes has been converted or removed.");
                    approvedClasspathEntries.remove(oacp);
                    approvedClasspathEntries.add(acp);
                    save();
                    return new ConversionCheckResult(oldHash, hash, true, true);
                }
            }
        }
        return new ConversionCheckResult(hash, hash, false, false);
    }

    @Restricted(NoExternalUse.class) // for use from Jelly
    public static abstract class PendingThing {

        /** @deprecated only used from historical records */
        @Deprecated private String user;
        
        private @NonNull ApprovalContext context;

        PendingThing(@NonNull ApprovalContext context) {
            this.context = context;
        }

        public @NonNull ApprovalContext getContext() {
            return context;
        }

        private Object readResolve() {
            if (user != null) {
                context = ApprovalContext.create().withUser(user);
                user = null;
            }
            return this;
        }

    }

    @Restricted(NoExternalUse.class) // for use from Jelly
    public static final class PendingScript extends PendingThing {
        public final String script;
        private final String language;
        PendingScript(@NonNull String script, @NonNull Language language, @NonNull ApprovalContext context) {
            super(context);
            this.script = script;
            this.language = language.getName();
        }
        public String getHash() {
            return DEFAULT_HASHER.hash(script, language);
        }
        public Language getLanguage() {
            for (Language l : ExtensionList.lookup(Language.class)) {
                if (l.getName().equals(language)) {
                    return l;
                }
            }
            return new Language() {
                @NonNull
                @Override public String getName() {
                    return language;
                }
                @NonNull
                @Override public String getDisplayName() {
                    return "<missing language: " + language + ">";
                }
            };
        }
        @Override public int hashCode() {
            return script.hashCode() ^ language.hashCode();
        }
        @Override public boolean equals(Object obj) {
            // Intentionally do not consider context in equality check.
            return obj instanceof PendingScript && ((PendingScript) obj).language.equals(language) && ((PendingScript) obj).script.equals(script);
        }
    }

    @Restricted(NoExternalUse.class) // for use from Jelly
    public static final class PendingSignature extends PendingThing {
        public final String signature;
        public final boolean dangerous;
        PendingSignature(@NonNull String signature, boolean dangerous, @NonNull ApprovalContext context) {
            super(context);
            this.signature = signature;
            this.dangerous = dangerous;
        }
        public String getHash() {
            // Security important, just for UI:
            return Integer.toHexString(hashCode());
        }
        @Override public int hashCode() {
            return signature.hashCode();
        }
        @Override public boolean equals(Object obj) {
            return obj instanceof PendingSignature && ((PendingSignature) obj).signature.equals(signature);
        }
    }

    /**
     * A classpath entry requiring approval by an administrator.
     * 
     * They are distinguished only with hashes,
     * but other additional information is provided for possible administrator use.
     * (Currently no context information is actually displayed, since the entry could be used from many scripts, so this might be misleading.)
     */
    @Restricted(NoExternalUse.class) // for use from Jelly
    public static final class PendingClasspathEntry extends PendingThing implements Comparable<PendingClasspathEntry> {
        private final String hash;
        private final URL url;
        
        private static final ApprovalContext SEARCH_APPROVAL_CONTEXT = ApprovalContext.create();
        private static URL SEARCH_APPROVAL_URL;
        
        static {
            try {
                SEARCH_APPROVAL_URL = new URL("http://invalid.url/do/not/use");
            } catch (Throwable e) {
                // Should not happen
                LOG.log(Level.WARNING, "Unexpected exception", e);
            }
        }
        
        PendingClasspathEntry(@NonNull String hash, @NonNull URL url, @NonNull ApprovalContext context) {
            super(context);
             // hash should be stored as files located at the classpath can be modified.
            this.hash = hash;
            this.url = url;
        }
        
        public @NonNull String getHash() {
            return hash;
        }
        
        public @NonNull URL getURL() {
            return url;
        }
        @Override public int hashCode() {
            return getHash().hashCode();
        }
        @Override public boolean equals(Object obj) {
            return obj instanceof PendingClasspathEntry && ((PendingClasspathEntry) obj).getHash().equals(getHash());
        }
        @Override public int compareTo(PendingClasspathEntry o) {
            return hash.compareTo(o.hash);
        }
        
        public static @NonNull PendingClasspathEntry searchKeyFor(@NonNull String hash) {
            return new PendingClasspathEntry(hash, SEARCH_APPROVAL_URL, SEARCH_APPROVAL_CONTEXT);
        }
    }

    private final LinkedHashSet<PendingScript> pendingScripts = new LinkedHashSet<>();

    private final LinkedHashSet<PendingSignature> pendingSignatures = new LinkedHashSet<>();

    private /*final*/ TreeSet<PendingClasspathEntry> pendingClasspathEntries;

    @CheckForNull
    private PendingClasspathEntry getPendingClasspathEntry(@NonNull String hash) {
        PendingClasspathEntry e = pendingClasspathEntries.floor(PendingClasspathEntry.searchKeyFor(hash));
        if (e != null && e.hash.equals(hash)) {
            return e;
        } else {
            return null;
        }
    }

    /* for test */ void addPendingClasspathEntry(PendingClasspathEntry pcp) {
        if (!isForceSandboxForCurrentUser()) {
            pendingClasspathEntries.add(pcp);
        }
    }

    @DataBoundConstructor
    public ScriptApproval() {
        load();
    }

    @Override
    public synchronized void load() {
        clear();
        super.load();
        // Check for loaded class directories
        boolean changed = false;
        int dcp = 0;
        for (Iterator<ApprovedClasspathEntry> i = approvedClasspathEntries.iterator(); i.hasNext();) {
            final ApprovedClasspathEntry entry = i.next();
            if (entry.isClassDirectory()) {
                i.remove();
                changed = true;
            }
            if (!DEFAULT_HASHER.pattern().matcher(entry.hash).matches()) {
                dcp++;
            }
        }
        int dsh = countDeprecatedApprovedScriptHashes();
        if (dcp > 0 || dsh > 0) {
            LOG.log(Level.WARNING, "There are {0} deprecated approved script hashes " +
                    "and {1} deprecated approved classpath hashes. " +
                    "They will be rehashed upon next use and that may cause performance issues " +
                    "until all of them are converted or removed.", new Object[]{dsh, dcp});
        }
        if (changed) {
            save();
        }
        try {
            configurationChanged();
        } catch (IOException x) {
            LOG.log(Level.SEVERE, "Malformed signature entry in scriptApproval.xml: '" + x.getMessage() + "'");
        }
    }

    private void clear() {
        approvedScriptHashes.clear();
        approvedSignatures.clear();
        pendingScripts.clear();
        pendingSignatures.clear();
        /* can be null when upgraded from old versions.*/
        if (aclApprovedSignatures == null) {
            aclApprovedSignatures = new TreeSet<>();
        } else {
            aclApprovedSignatures.clear();
        }
        if (approvedClasspathEntries == null) {
            approvedClasspathEntries = new TreeSet<>();
        } else {
            approvedClasspathEntries.clear();
        }
        if (pendingClasspathEntries == null) {
            pendingClasspathEntries = new TreeSet<>();
        } else {
            pendingClasspathEntries.clear();
        }
    }

    @Restricted(NoExternalUse.class)
    public synchronized boolean hasDeprecatedApprovedScriptHashes() {
        return countDeprecatedApprovedScriptHashes() > 0;
    }

    @Restricted(NoExternalUse.class)
    public synchronized int countDeprecatedApprovedScriptHashes() {
        int dsh = 0;
        for (String hash : approvedScriptHashes) {
            if (!DEFAULT_HASHER.pattern().matcher(hash).matches()) {
                dsh++;
            }
        }
        return dsh;
    }

    @Restricted(NoExternalUse.class)
    public synchronized int countDeprecatedApprovedClasspathHashes() {
        int dcp = 0;
        for (ApprovedClasspathEntry entry : approvedClasspathEntries) {
            if (!DEFAULT_HASHER.pattern().matcher(entry.getHash()).matches()) {
                dcp++;
            }
        }
        return dcp;
    }

    @Restricted(NoExternalUse.class)
    public synchronized boolean hasDeprecatedApprovedClasspathHashes() {
        return countDeprecatedApprovedClasspathHashes() > 0;
    }

    /** Nothing has ever been approved or is pending. */
    synchronized boolean isEmpty() {
        return approvedScriptHashes.isEmpty() &&
               approvedSignatures.isEmpty() &&
               aclApprovedSignatures.isEmpty() &&
               approvedClasspathEntries.isEmpty() &&
               pendingScripts.isEmpty() &&
               pendingSignatures.isEmpty() &&
               pendingClasspathEntries.isEmpty();
    }

    /**
     * Used when someone is configuring a script.
     * Typically you would call this from a {@link DataBoundConstructor}.
     * It should also be called from a {@code readResolve} method (which may then simply return {@code this}),
     * so that administrators can for example POST to {@code config.xml} and have their scripts be considered approved.
     * <p>If the script has already been approved, this does nothing.
     * Otherwise, if this user has the {@link Jenkins#ADMINISTER} permission (and is not {@link ACL#SYSTEM2})
     * and a corresponding flag is set to {@code true}, or Jenkins is running without security, it is added to the approved list.
     * Otherwise, it is added to the pending list.
     * @param script the text of a possibly novel script
     * @param language the language in which it is written
     * @param context any additional information about how where or by whom this is being configured
     * @param approveIfAdmin indicates whether script should be approved if current user has admin permissions
     * @return {@code script}, for convenience
     */
    public synchronized String configuring(@NonNull String script, @NonNull Language language, @NonNull ApprovalContext context, boolean approveIfAdmin) {
        final ConversionCheckResult result = checkAndConvertApprovedScript(script, language);
        if (!result.approved) {
            if (!Jenkins.get().isUseSecurity() || 
                    (ALLOW_ADMIN_APPROVAL_ENABLED &&
                    ((Jenkins.getAuthentication2() != ACL.SYSTEM2 && Jenkins.get().hasPermission(Jenkins.ADMINISTER))
                            && (ADMIN_AUTO_APPROVAL_ENABLED || approveIfAdmin)))) {
                approvedScriptHashes.add(result.newHash);
                //Pending scripts are not stored with a precalculated hash, so no need to remove any old hashes
                removePendingScript(result.newHash);
            } else {
                String key = context.getKey();
                if (key != null) {
                    pendingScripts.removeIf(pendingScript -> key.equals(pendingScript.getContext().getKey()));
                }
                if (!isForceSandboxForCurrentUser()) {
                    pendingScripts.add(new PendingScript(script, language, context));
                }
            }
            save();
        }
        return script;
    }

    /**
     * @deprecated Use {@link #configuring(String, Language, ApprovalContext, boolean)} instead
     */
    @Deprecated
    public String configuring(@NonNull String script, @NonNull Language language, @NonNull ApprovalContext context) {
        return this.configuring(script, language, context, false);
    }

    /**
     * Called when a script is about to be used (evaluated).
     * @param script a possibly unapproved script
     * @param language the language in which it is written
     * @return {@code script}, for convenience
     * @throws UnapprovedUsageException in case it has not yet been approved
     */
    public synchronized String using(@NonNull String script, @NonNull Language language) throws UnapprovedUsageException {
        if (script.length() == 0) {
            // As a special case, always consider the empty script preapproved, as this is usually the default for new fields,
            // and in many cases there is some sensible behavior for an emoty script which we want to permit.
            return script;
        }
        ConversionCheckResult result = checkAndConvertApprovedScript(script, language);
        if (!result.approved) {
            // Probably need not add to pendingScripts, since generally that would have happened already in configuring.
            throw new UnapprovedUsageException(result.newHash);
        }
        return script;
    }

    // Only for testing
    synchronized boolean isScriptHashApproved(String hash) {
        return approvedScriptHashes.contains(hash);
    }

    /**
     * Called when configuring a classpath entry.
     * Usage is similar to {@link #configuring(String, Language, ApprovalContext, boolean)}.
     * @param entry entry to be configured
     * @param context any additional information
     * @throws IllegalStateException {@link Jenkins} instance is not ready
     */
    public synchronized void configuring(@NonNull ClasspathEntry entry, @NonNull ApprovalContext context) {
        // In order to try to minimize changes for existing class directories that could be saved
        // - Class directories are ignored here (issuing a warning)
        // - When trying to use them, the job will fail
        // - Going to the configuration page you'll have the validation error in the classpath entry
        if (entry.isClassDirectory()) {
            LOG.log(Level.WARNING, "Classpath {0} is a class directory, which are not allowed. Ignored in configuration, use will be rejected",
                    entry.getURL());
            return;
        }
        //TODO: better error propagation
        URL url = entry.getURL();
        ConversionCheckResult result;
        try {
            result = checkAndConvertApprovedClasspath(url);
        } catch (IOException x) {
            // This is a case the path doesn't really exist
            LOG.log(Level.WARNING, null, x);
            return;
        }

        if (!result.approved) {
            boolean shouldSave = false;
            PendingClasspathEntry pcp = new PendingClasspathEntry(result.newHash, url, context);
            if (!Jenkins.get().isUseSecurity() ||
                    ((Jenkins.getAuthentication2() != ACL.SYSTEM2 && Jenkins.get().hasPermission(Jenkins.ADMINISTER))
                            && (ADMIN_AUTO_APPROVAL_ENABLED || entry.isShouldBeApproved() || !StringUtils.equals(entry.getOldPath(), entry.getPath())))) {
                LOG.log(Level.FINE, "Classpath entry {0} ({1}) is approved as configured with ADMINISTER permission.", new Object[] {url, result.newHash});
                ApprovedClasspathEntry acp = new ApprovedClasspathEntry(result.newHash, url);
                pendingClasspathEntries.remove(pcp);
                approvedClasspathEntries.add(acp);
                shouldSave = true;
            } else {
                if (!isForceSandboxForCurrentUser() && pendingClasspathEntries.add(pcp)) {
                    LOG.log(Level.FINE, "{0} ({1}) is pending", new Object[] {url, result.newHash});
                    shouldSave = true;
                }
            }
            if (shouldSave) {
                save();
            }
        }
    }
    
    /**
     * Like {@link #checking(String, Language, boolean)} but for classpath entries.
     * However, this method does not actually check whether the classpath entry is approved, 
     * because it would have to connect to the URL and download the contents, 
     * which may be unsafe if this is called via a web method by an unprivileged user
     * (This is automatic if use {@link ClasspathEntry} as a configuration element.)
     * @param entry the classpath entry to verify
     * @return whether it will be approved
     * @throws IllegalStateException {@link Jenkins} instance is not ready
     */
    public synchronized FormValidation checking(@NonNull ClasspathEntry entry) {
        //TODO: better error propagation
        if (entry.isClassDirectory()) {
            return FormValidation.error(Messages.ClasspathEntry_path_noDirsAllowed());
        }
        // We intentionally do not call hashClasspathEntry because that method downloads the contents
        // of the URL in order to hash it, making it an attractive DoS vector, and we do not have enough
        // context here to be able to easily perform an appropriate permission check.
        return FormValidation.ok();
    }
    
    /**
     * Asserts that a classpath entry is approved.
     * Also records it as a pending entry if not approved.
     * @param entry a classpath entry
     * @throws IOException when failed to the entry is inaccessible
     * @throws UnapprovedClasspathException when the entry is not approved
     */
    public synchronized void using(@NonNull ClasspathEntry entry) throws IOException, UnapprovedClasspathException {
        URL url = entry.getURL();
        // Don't add it to pending if it is a class directory
        if (entry.isClassDirectory()) {
            LOG.log(Level.WARNING, "Classpath {0} is a class directory, which are not allowed.", url);
            throw new UnapprovedClasspathException("classpath entry %s is a class directory, which are not allowed.", url, "");
        }
        ConversionCheckResult result = checkAndConvertApprovedClasspath(url);

        if (!result.approved) {
            // Never approve classpath here.
            ApprovalContext context = ApprovalContext.create();
            if (!isForceSandboxForCurrentUser() && pendingClasspathEntries.add(new PendingClasspathEntry(result.newHash, url, context))) {
                LOG.log(Level.FINE, "{0} ({1}) is pending.", new Object[]{url, result.newHash});
                save();
            }
            throw new UnapprovedClasspathException(url, result.newHash);
        }
        
        LOG.log(Level.FINER, "{0} ({1}) had been approved", new Object[] {url, result.newHash});
    }

    /**
     * To be used from form validation, in a {@code doCheckFieldName} method.
     * @param script a possibly unapproved script
     * @param language the language in which it is written
     * @param willBeApproved whether script is going to be approved after configuration is saved
     * @return a warning indicating that admin approval will be needed in case current user does not have
     *          {@link Jenkins#ADMINISTER} permission; a warning indicating that script is not yet approved if user has such
     *          permission and {@code willBeApproved} is false; a message indicating that script will be approved if user
     *          has such permission and {@code willBeApproved} is true; nothing if script is empty; a corresponding message
     *          if script is approved
     */
    public synchronized FormValidation checking(@NonNull String script, @NonNull Language language, boolean willBeApproved) {
        if (StringUtils.isEmpty(script)) {
            return FormValidation.ok();
        }
        final ConversionCheckResult result = checkAndConvertApprovedScript(script, language);
        if (result.approved) {
            return FormValidation.okWithMarkup(isForceSandboxForCurrentUser() ?
                                               Messages.ScriptApproval_ForceSandBoxMessage() :
                                               "The script is already approved");
        }

        if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
            return FormValidation.warningWithMarkup(isForceSandboxForCurrentUser() ?
                                                    Messages.ScriptApproval_ForceSandBoxMessage() :
                                                    Messages.ScriptApproval_PipelineMessage());
        } else {
            String forceSandboxMessage = isForceSandbox() ?
                                         Messages.ScriptApproval_AdminUserAlert() :
                                         "";

            if ((ALLOW_ADMIN_APPROVAL_ENABLED && (willBeApproved || ADMIN_AUTO_APPROVAL_ENABLED)) || !Jenkins.get().isUseSecurity()) {
                return FormValidation.okWithMarkup(forceSandboxMessage + "The script has not yet been approved, "
                                                   + "but it will be approved on save.");
            }
            String approveScript = "<a class='jenkins-button script-approval-approve-link' data-base-url='" + Jenkins.get().getRootUrl() + ScriptApproval.get().getUrlName() + "' data-hash='" + result.newHash + "'>Approve script</a>";
            return FormValidation.okWithMarkup(forceSandboxMessage + "The script is not approved and will not be approved on save. " +
                    "Either modify the script to match an already approved script, approve it explicitly on the " +
                    "<a target='blank' href='"+ Jenkins.get().getRootUrl() + ScriptApproval.get().getUrlName() + "'>Script Approval Configuration</a> page after save, or approve this version of the script. " +
                    approveScript);
        }
    }

    @Restricted(NoExternalUse.class)
    @POST
    // can not call this method doApproveScript as that collides with the javascript binding in #approveScript
    public synchronized void doApproveScriptHash(@QueryParameter(required=true) String hash) throws IOException {
        approveScript(hash);
    }

    /**
     * @deprecated Use {@link #checking(String, Language, boolean)} instead
     */
    @Deprecated
    public synchronized FormValidation checking(@NonNull String script, @NonNull Language language) {
        return this.checking(script, language, false);
    }

    synchronized boolean isClasspathEntryApproved(URL url) {
        try {
            final ConversionCheckResult result = checkAndConvertApprovedClasspath(url);
            return result.approved;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Unconditionally approve a script.
     * Does no access checks and does not automatically save changes to disk.
     * Useful mainly for testing.
     * @param script the text of a possibly novel script
     * @param language the language in which it is written
     * @return {@code script}, for convenience
     */
    public synchronized String preapprove(@NonNull String script, @NonNull Language language) {
        approvedScriptHashes.add(DEFAULT_HASHER.hash(script, language.getName()));
        return script;
    }

    /**
     * Unconditionally approves all pending scripts.
     * Does no access checks and does not automatically save changes to disk.
     * Useful mainly for testing in combination with {@code @LocalData}.
     */
    public synchronized void preapproveAll() {
        for (PendingScript ps : pendingScripts) {
            approvedScriptHashes.add(ps.getHash());
        }
        pendingScripts.clear();
    }

    /**
     * To be called when a sandbox rejects access for a script not using manual approval.
     * The signature of the failing method (if known) will be added to the pending list.
     * @param x an exception with the details
     * @param context any additional information about where or by whom this script was run
     * @return {@code x}, for convenience in rethrowing
     * @deprecated Unnecessary if using {@link GroovySandbox#enter}.
     */
    @Deprecated
    public synchronized RejectedAccessException accessRejected(@NonNull RejectedAccessException x, @NonNull ApprovalContext context) {
        String signature = x.getSignature();
        if (signature != null && !isForceSandboxForCurrentUser() && pendingSignatures.add(new PendingSignature(signature, x.isDangerous(), context))) {
            save();
        }
        return x;
    }

    private static final ThreadLocal<Stack<Consumer<RejectedAccessException>>> callbacks = ThreadLocal.withInitial(Stack::new);

    @Restricted(NoExternalUse.class)
    public static void maybeRegister(@NonNull RejectedAccessException x) {
        for (Consumer<RejectedAccessException> callback : callbacks.get()) {
            callback.accept(x);
        }
    }

    @Restricted(NoExternalUse.class)
    public static void pushRegistrationCallback(Consumer<RejectedAccessException> callback) {
        callbacks.get().push(callback);
    }

    @Restricted(NoExternalUse.class)
    public static void popRegistrationCallback() {
        callbacks.get().pop();
    }

    @DataBoundSetter
    public synchronized void setApprovedSignatures(String[] signatures) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedSignatures.clear();
        List<String> goodSignatures = new ArrayList<>(signatures.length);
        for (String signature : signatures) {
            try {
                StaticWhitelist.parse(signature);
                goodSignatures.add(signature);
            } catch (IOException e) {
                LOG.warning("Ignoring malformed signature: " + signature
                        + " (Occurred exception: " + e + ")");
            }
        }
        approvedSignatures.addAll(goodSignatures);
        save();
        reconfigure();
    }

    @Restricted(NoExternalUse.class) // Jelly, implementation
    public synchronized String[] getApprovedSignatures() {
        return approvedSignatures.toArray(new String[approvedSignatures.size()]);
    }

    @Restricted(NoExternalUse.class) // Jelly, implementation
    public synchronized String[] getDangerousApprovedSignatures() {
        List<String> dangerous = new ArrayList<>();
        for (String sig : approvedSignatures) {
            if (StaticWhitelist.isBlacklisted(sig)) {
                dangerous.add(sig);
            }
        }
        return dangerous.toArray(new String[dangerous.size()]);
    }

    @Restricted(NoExternalUse.class) // Jelly, implementation
    public synchronized String[] getAclApprovedSignatures() {
        return aclApprovedSignatures.toArray(new String[aclApprovedSignatures.size()]);
    }

    @DataBoundSetter
    public synchronized void setApprovedScriptHashes(String[] scriptHashes) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedScriptHashes.clear();
        for (String scriptHash : scriptHashes) {
            if (StringUtils.isNotEmpty(scriptHash)) {
                if (DEFAULT_HASHER.pattern().matcher(scriptHash).matches()) {
                    approvedScriptHashes.add(scriptHash);
                } else {
                    boolean allowed = false;
                    for (Hasher hasher : Hasher.values()) {
                        if (hasher != DEFAULT_HASHER && hasher.pattern().matcher(scriptHash).matches()) {
                            allowed = true;
                            break;
                        }
                    }
                    if (allowed) {
                        LOG.warning(() -> "Adding deprecated script hash that will be converted on next use: " + scriptHash);
                        approvedScriptHashes.add(scriptHash);
                    } else {
                        LOG.warning(() -> "Ignoring malformed script hash: " + scriptHash);
                    }
                }
            }
        }
        save();
        reconfigure();
    }

    @DataBoundSetter
    public void setForceSandbox(boolean forceSandbox) {
        this.forceSandbox = forceSandbox;
        save();
    }


    public boolean isForceSandbox() {
        return forceSandbox;
    }

    //ForceSandbox restrictions does not apply to ADMINISTER users.
    public boolean isForceSandboxForCurrentUser() {
        return forceSandbox && !Jenkins.get().hasPermission(Jenkins.ADMINISTER);
    }

    @Restricted(NoExternalUse.class) // Jelly, tests, implementation
    public synchronized String[] getApprovedScriptHashes() {
        return approvedScriptHashes.toArray(new String[approvedScriptHashes.size()]);
    }

    private synchronized void configurationChanged() throws IOException {
        // Do not use lookupSingleton: ScriptApprovalLoadingTest.dynamicLoading
        ApprovedWhitelist instance = ExtensionList.lookup(Whitelist.class).get(ApprovedWhitelist.class);
        if (instance == null) {
            throw new IllegalStateException("Failed to find ApprovedWhitelist");
        }
        LOG.fine("resetting");
        synchronized (instance) {
            instance.pendingDelegate = new AclAwareWhitelist(new StaticWhitelist(approvedSignatures), new StaticWhitelist(aclApprovedSignatures));
        }
    }

    @Restricted(NoExternalUse.class) // implementation
    @Extension public static final class ApprovedWhitelist extends ProxyWhitelist {

        private @CheckForNull Whitelist pendingDelegate;

        @Override protected synchronized void beforePermits() {
            if (pendingDelegate != null) {
                LOG.fine("refreshing");
                reset(Set.of(pendingDelegate));
                pendingDelegate = null;
            } else {
                LOG.finer("no need to refresh");
            }
        }

    }

    @Override public String getIconFileName() {
        return null;
    }

    @Override public String getUrlName() {
        return "scriptApproval";
    }

    @Restricted(NoExternalUse.class) // for use from Jelly
    public Set<PendingScript> getPendingScripts() {
        return pendingScripts;
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public void approveScript(String hash) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        synchronized (this) {
            approvedScriptHashes.add(hash);
            removePendingScript(hash);
            save();
        }

        try (ACLContext ctx = ACL.as2(ACL.SYSTEM2)) {
            for (ApprovalListener listener : ExtensionList.lookup(ApprovalListener.class)) {
                listener.onApproved(hash);
            }
        }
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized void denyScript(String hash) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedScriptHashes.remove(hash);
        removePendingScript(hash);
        save();
    }

    synchronized void removePendingScript(String hash) {
        Iterator<PendingScript> it = pendingScripts.iterator();
        while (it.hasNext()) {
            if (it.next().getHash().equals(hash)) {
                it.remove();
                break;
            }
        }
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized void clearApprovedScripts() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedScriptHashes.clear();
        save();
    }


    /**
     * Clears {@link #approvedScriptHashes} from all entries not matching {@link #DEFAULT_HASHER}.
     * @throws IOException if so when saving to disk.
     */
    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized void clearDeprecatedApprovedScripts() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedScriptHashes.removeIf(s -> !DEFAULT_HASHER.pattern().matcher(s).matches());
        save();
    }

    @Restricted(NoExternalUse.class)
    public String getSpinnerIconClassName() {
        return BallColor.GREY_ANIME.getIconClassName();
    }

    /**
     * Schedules a {@link Thread} task that rehashes/converts all approved classpath entries
     * that are hashed not using {@link #DEFAULT_HASHER}.
     */
    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized void convertDeprecatedApprovedClasspathEntries() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (!isConvertingDeprecatedApprovedClasspathEntries()) {
            final List<ApprovedClasspathEntry> entries = approvedClasspathEntries.stream()
                    .filter(e -> !DEFAULT_HASHER.pattern().matcher(e.getHash()).matches())
                    .collect(Collectors.toList());
            if (!entries.isEmpty()) {
                LOG.log(Level.INFO, "Scheduling conversion of {0} deprecated approved classpathentry hashes.", entries.size());
                convertDeprecatedApprovedClasspathEntriesThread = new Thread(() -> {
                    final Map<String, ApprovedClasspathEntry> result = new HashMap<>();
                    for (int i = 0; i < entries.size(); i++) {
                        final ApprovedClasspathEntry entry = entries.get(i);
                        final URL entryURL = entry.getURL();
                        LOG.log(Level.INFO, String.format("Converting %s\t(%d/%d)", entryURL, i + 1, entries.size()));
                        try {
                            final String hash = DEFAULT_HASHER.hashClasspathEntry(entryURL);
                            result.put(entryURL.toExternalForm(), new ApprovedClasspathEntry(hash, entryURL));
                        } catch (Throwable e) {
                            LOG.log(Level.WARNING, "Failed to convert " + entryURL, e);
                        }
                        Thread.yield(); //Technically not needed as there is plenty of IO happening in this thread.
                    }
                    synchronized (ScriptApproval.this) {
                        approvedClasspathEntries.removeIf(e -> result.containsKey(e.getURL().toExternalForm()));
                        approvedClasspathEntries.addAll(result.values());
                        try {
                            save();
                        } catch (Exception e) {
                            LOG.log(Level.WARNING, "Failed to store conversion result.", e);
                        }
                    }
                    LOG.info("Conversion done.");
                    synchronized (ScriptApproval.this) {
                        convertDeprecatedApprovedClasspathEntriesThread = null;
                    }
                }, "Approved Classpaths rehasher");
                convertDeprecatedApprovedClasspathEntriesThread.setDaemon(true);
                convertDeprecatedApprovedClasspathEntriesThread.start();
                LOG.fine("Background conversion task scheduled.");
            } else {
                LOG.info("Nothing to convert.");
            }
        } else {
            LOG.fine("Background conversion task already running.");
        }
    }

    /**
     * Checks if {@link #convertDeprecatedApprovedClasspathEntriesThread} is active.
     * @return true if so.
     */
    @Restricted(NoExternalUse.class)
    public synchronized boolean isConvertingDeprecatedApprovedClasspathEntries() {
        return convertDeprecatedApprovedClasspathEntriesThread != null
                && convertDeprecatedApprovedClasspathEntriesThread.isAlive();
    }

    @Restricted(NoExternalUse.class) // for use from Jelly
    public Set<PendingSignature> getPendingSignatures() {
        return pendingSignatures;
    }

    private synchronized String[][] reconfigure() throws IOException {
        configurationChanged();
        return new String[][] {getApprovedSignatures(), getAclApprovedSignatures(), getDangerousApprovedSignatures()};
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized String[][] approveSignature(String signature) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        pendingSignatures.remove(new PendingSignature(signature, false, ApprovalContext.create()));
        approvedSignatures.add(signature);
        save();
        return reconfigure();
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized String[][] aclApproveSignature(String signature) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        pendingSignatures.remove(new PendingSignature(signature, false, ApprovalContext.create()));
        aclApprovedSignatures.add(signature);
        save();
        return reconfigure();
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized void denySignature(String signature) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        pendingSignatures.remove(new PendingSignature(signature, false, ApprovalContext.create()));
        save();
    }

    // TODO nicer would be to allow the user to actually edit the list directly (with syntax checks)
    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized String[][] clearApprovedSignatures() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedSignatures.clear();
        aclApprovedSignatures.clear();
        save();
        // Should be [[], []] but still returning it for consistency with approve methods.
        return reconfigure();
    }
    
    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod public synchronized String[][] clearDangerousApprovedSignatures() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        Iterator<String> it = approvedSignatures.iterator();
        while (it.hasNext()) {
            if (StaticWhitelist.isBlacklisted(it.next())) {
                it.remove();
            }
        }

        it = aclApprovedSignatures.iterator();
        while (it.hasNext()) {
            if (StaticWhitelist.isBlacklisted(it.next())) {
                it.remove();
            }
        }

        save();
        return reconfigure();
    }

    @Restricted(NoExternalUse.class)
    public synchronized List<ApprovedClasspathEntry> getApprovedClasspathEntries() {
        ArrayList<ApprovedClasspathEntry> r = new ArrayList<>(approvedClasspathEntries);
        r.sort(Comparator.comparing(o -> o.url.toString()));
        return r;
    }

    @Restricted(NoExternalUse.class)
    public synchronized List<PendingClasspathEntry> getPendingClasspathEntries() {
        List<PendingClasspathEntry> r = new ArrayList<>(pendingClasspathEntries);
        r.sort(Comparator.comparing(o -> o.url.toString()));
        return r;
    }

    @Restricted(NoExternalUse.class) // for use from Ajax
    @JavaScriptMethod
    public JSON getClasspathRenderInfo() {
        JSONArray pendings = new JSONArray();
        for (PendingClasspathEntry cp : getPendingClasspathEntries()) {
            pendings.add(new JSONObject().element("hash", cp.getHash()).element("path", ClasspathEntry.urlToPath(cp.getURL())));
        }
        JSONArray approveds = new JSONArray();
        for (ApprovedClasspathEntry cp : getApprovedClasspathEntries()) {
            approveds.add(new JSONObject().element("hash", cp.getHash()).element("path", ClasspathEntry.urlToPath(cp.getURL())));
        }
        return new JSONArray().element(pendings).element(approveds);
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod
    public synchronized JSON approveClasspathEntry(String hash) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        URL url = null;
        synchronized (this) {
            final PendingClasspathEntry cp = getPendingClasspathEntry(hash);
            if (cp != null) {
                pendingClasspathEntries.remove(cp);
                url = cp.getURL();
                approvedClasspathEntries.add(new ApprovedClasspathEntry(hash, url));
                save();
            }
        }
        if (url != null) {
            try (ACLContext ctx = ACL.as2(ACL.SYSTEM2)) {
                for (ApprovalListener listener : ExtensionList.lookup(ApprovalListener.class)) {
                    listener.onApprovedClasspathEntry(hash, url);
                }
            }
        }
        return getClasspathRenderInfo();
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod
    public synchronized JSON denyClasspathEntry(String hash) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        PendingClasspathEntry cp = getPendingClasspathEntry(hash);
        if (cp != null) {
            pendingClasspathEntries.remove(cp);
            save();
        }
        return getClasspathRenderInfo();
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod
    public synchronized JSON denyApprovedClasspathEntry(String hash) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (approvedClasspathEntries.remove(new ApprovedClasspathEntry(hash, null))) {
            save();
        }
        return getClasspathRenderInfo();
    }

    @Restricted(NoExternalUse.class) // for use from AJAX
    @JavaScriptMethod
    public synchronized JSON clearApprovedClasspathEntries() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        approvedClasspathEntries.clear();
        save();
        return getClasspathRenderInfo();
    }

    @Restricted(NoExternalUse.class)
    @Extension
    public static class FormValidationPageDecorator extends PageDecorator {}

    public static <T> boolean shouldHideSandbox(@CheckForNull T instance, Predicate<T> isSandbox){
        return get().isForceSandboxForCurrentUser()
               && (instance == null || isSandbox.test(instance));
    }

    public static void validateSandbox(boolean sandbox) throws Descriptor.FormException{
        if (!sandbox && get().isForceSandboxForCurrentUser()) {
            throw new Descriptor.FormException(Messages.ScriptApproval_SandboxCantBeDisabled(), "sandbox");
        }
    }
}
