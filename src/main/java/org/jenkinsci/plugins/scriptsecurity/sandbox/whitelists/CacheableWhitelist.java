package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

/**
 * Marker interface indicating results of permission checks do not change unless the list of entries is modified
 *  and depend ONLY on the Field/Method/Constructor actually being invoked, irrespective of classloader.
 *  That means you must be able to represent the WhiteList entry with a String signature of className + method/field signature.
 * @author Sam Van Oort
 */
public interface CacheableWhitelist {
}
