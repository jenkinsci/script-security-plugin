/*
 * The MIT License
 *
 * Copyright (c) 2020, CloudBees, Inc.
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
package org.jenkinsci.plugins.scriptsecurity.scripts.metadata;

import hudson.XmlFile;
import jenkins.model.Jenkins;
import org.apache.commons.io.FileUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@Restricted(NoExternalUse.class)
public class MetadataStorage {
    private static final Logger LOGGER = Logger.getLogger(MetadataStorage.class.getName());
    /**
     * Currently only lowercase hex characters are necessary but we will need additional characters
     * to support SHA-256 or other, in order to support migration.
     *
     * This prevents path traversal attempts
     */
    private static final Pattern HASH_REGEX = Pattern.compile("[a-zA-Z0-9_\\-]+");
    private static final String METADATA_FILE_NAME = "metadata.xml";
    private static final String SCRIPT_FILE_NAME = "script.txt";

    private final File metadataFolder;

    /**
     * Metadata about full scripts. 
     * They can exist before approval and remains after revocation.  
     */
    private HashMap<String, FullScriptMetadata> hashToMetadata;

    public MetadataStorage(@Nonnull String metadataFolderPath) {
        this.metadataFolder = new File(Jenkins.getInstance().getRootDir(), metadataFolderPath);
        if (metadataFolder.mkdirs()) {
            LOGGER.log(Level.FINER, "Metadata storage folder created: {0}", metadataFolder.getAbsolutePath());
        }
    }

    public @Nonnull List<HashAndFullScriptMetadata> getMetadataUsingHashes(@Nonnull Collection<String> approvedScriptHashes) {
        this.ensureLoaded();
        List<HashAndFullScriptMetadata> result = new ArrayList<>(approvedScriptHashes.size());

        for (String hash : approvedScriptHashes) {
            FullScriptMetadata metadata = hashToMetadata.getOrDefault(hash, FullScriptMetadata.EMPTY);
            HashAndFullScriptMetadata hashAndMeta = new HashAndFullScriptMetadata(hash, metadata);
            result.add(hashAndMeta);
        }
        return result;
    }

    /**
     * Lazy loading to avoid slowing down the startup of the instance
     */
    private void ensureLoaded() {
        if (hashToMetadata != null) {
            return;
        }

        LOGGER.log(Level.INFO, "Loading script approval metadata...");
        long startTime = System.currentTimeMillis();

        loadAllMetadata();

        long endTime = System.currentTimeMillis();
        LOGGER.log(Level.INFO, "All metadata loaded in {0} ms", endTime - startTime);
    }

    /**
     * This method could be called by Script Console to reload the metadata
     * 
     * org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval.get().metadataStorage.loadAllMetadata()
     */
    private void loadAllMetadata() {
        hashToMetadata = new HashMap<>();
        String[] hashes = metadataFolder.list();
        for (int i = 0; i < hashes.length; i++) {
            String hash = hashes[i];
            File metadataFile = new File(metadataFolder, hash + File.separator + METADATA_FILE_NAME);
            if (metadataFile.exists()) {
                XmlFile xmlFile = new XmlFile(metadataFile);
                try {
                    Object content = xmlFile.read();
                    if (content instanceof FullScriptMetadata) {
                        FullScriptMetadata metadata = (FullScriptMetadata) content;
                        this.hashToMetadata.put(hash, metadata);
                    } else {
                        LOGGER.log(Level.WARNING, "Invalid class read for the metadata for hash {0}, found: {1}", new Object[]{hash, content.getClass()});
                    }
                } catch (IOException e) {
                    LOGGER.log(Level.INFO, "Impossible to read the metadata for hash {0}.", hash);
                }
            }
        }
    }

    public @CheckForNull FullScriptMetadata getExisting(@Nonnull String hash) {
        ensureLoaded();
        return hashToMetadata.get(hash);
    }

    public void withMetadata(@Nonnull String hash, @CheckForNull String script, @Nonnull Consumer<FullScriptMetadata> consumer) {
        ensureLoaded();
        ensureValidHash(hash);

        FullScriptMetadata metadata = hashToMetadata.get(hash);
        if (metadata == null) {
            metadata = new FullScriptMetadata();
            hashToMetadata.put(hash, metadata);
        }

        consumer.accept(metadata);

        saveMetadata(hash, metadata);
        if (script != null) {
            saveScript(hash, script);
        }
    }

    public void removeHash(@Nonnull String hash) {
        ensureLoaded();
        ensureValidHash(hash);
        FullScriptMetadata metadata = hashToMetadata.remove(hash);
        if (metadata == null) {
            return;
        }

        deleteHashFolder(hash);
    }

    private void saveMetadata(@Nonnull String hash, @Nonnull FullScriptMetadata metadata) {
        File hashFolder = new File(metadataFolder, hash);
        if (hashFolder.mkdirs()) {
            LOGGER.log(Level.FINER, "Metadata folder created for hash {0}", hash);
        }

        XmlFile xmlFile = new XmlFile(new File(hashFolder, METADATA_FILE_NAME));
        try {
            xmlFile.write(metadata);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, e, () -> "Failed to save the metadata for hash: " + hash);
        }
    }

    private void deleteHashFolder(@Nonnull String hash) {
        File targetFolder = new File(metadataFolder, hash);

        try {
            boolean existed = targetFolder.exists();
            FileUtils.deleteDirectory(targetFolder);
            if (existed) {
                LOGGER.log(Level.FINER, "Metadata related to {0} removed", hash);
            } else {
                LOGGER.log(Level.FINER, "Metadata related to {0} did not exist", hash);
            }
        } catch (IOException e) {
            LOGGER.log(Level.FINE, "Impossible to delete the metadata folder found for {0}", hash);
        }
    }

    private void ensureValidHash(@Nonnull String hash) {
        if (!HASH_REGEX.matcher(hash).matches()) {
            throw new IllegalArgumentException("The provided hash is invalid: " + hash);
        }
    }

    /**
     * Assume the {@link #saveMetadata(String, FullScriptMetadata)} is called first to create the parent folder 
     */
    private void saveScript(@Nonnull String hash, @Nonnull String script) {
        File file = new File(metadataFolder, hash + File.separator + SCRIPT_FILE_NAME);
        try {
            FileUtils.write(file, script, StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, e, () -> "Failed to save the script for hash: " + hash);
        }
    }

    /**
     * Read the script if the file exists
     */
    public @CheckForNull String readScript(@Nonnull String hash) {
        ensureLoaded();
        ensureValidHash(hash);

        File file = new File(metadataFolder, hash + File.separator + SCRIPT_FILE_NAME);
        if (!file.exists()) {
            return null;
        }
        try {
            String script = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
            return script;
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, e, () -> "Failed to save the script for hash: " + hash);
        }
        return null;
    }
}
