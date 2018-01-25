package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

/**
 * Marker interface indicating results of permission checks do not change unless the list of entries is modified
 *  and depend ONLY on the Field/Method/Constructor actually being invoked.
 * @author Sam Van Oort
 */
public interface CacheableWhitelist {
}
