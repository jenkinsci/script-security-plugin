# Script Security Plugin

[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/script-security)](https://plugins.jenkins.io/script-security)
[![Changelog](https://img.shields.io/github/v/tag/jenkinsci/script-security-plugin?label=changelog)](https://github.com/jenkinsci/script-security-plugin/releases)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/script-security?color=blue)](https://plugins.jenkins.io/script-security)
## User’s guide
(adapted from information on [Template plugin in CloudBees Plugins guide](https://docs.cloudbees.com/docs/admin-resources/latest/plugins/template#template-sect-script-approval))

Various Jenkins plugins require that users define custom scripts, most commonly in the 
Groovy language, to customize Jenkins’s behavior. If everyone who writes these scripts is 
a Jenkins administrator—specifically if they have the Overall/RunScripts permission, used 
for example by the Script Console link—then they can write whatever scripts they like. 
These scripts may directly refer to internal Jenkins objects using the same API offered to 
plugins. Such users must be completely trusted, as they can do anything to Jenkins (even 
changing its security settings or running shell commands on the server).

However, if some script authors are “regular users” with only more limited permissions, 
such as Job/Configure, it is inappropriate to let them run arbitrary scripts. To support 
such a division of roles, the Script Security library plugin can be integrated into 
various feature plugins. It supports two related systems: script approval, and Groovy 
sandboxing.

### Script Approval
The first, and simpler, security system is to allow any kind of script to be run, but only 
with an administrator’s approval. There is a globally maintained list of approved scripts 
which are judged to not perform any malicious actions.

When an administrator saves some kind of configuration (for example, a job), any scripts 
it contains are automatically added to the approved list. They are ready to run with no 
further intervention. (“Saving” usually means from the web UI, but could also mean 
uploading a new XML configuration via REST or CLI.)

When a non-administrator saves a template configuration, a check is done whether any 
contained scripts have been edited from an approved text. (More precisely, whether the 
requested content has ever been approved before.) If it has not been approved, a request 
for approval of this script is added to a queue. (A warning is also displayed in the 
configuration screen UI when the current text of a script is not currently approved.)

An administrator may now go to _Manage Jenkins » In-process Script Approval_ where a list 
of scripts pending approval will be shown. Assuming nothing dangerous-looking is being 
requested, just click Approve to let the script be run henceforth.

If you try to run an unapproved script, it will simply fail, typically with a message 
explaining that it is pending approval. You may retry once the script has been approved. 
The details of this behavior may vary according to the feature plugin integrating this 
library.

### Groovy Sandboxing
Waiting for an administrator to approve every change to a script, no matter how seemingly 
trivial, could be unacceptable in a team spread across timezones or during tight 
deadlines. As an alternative option, the Script Security system lets Groovy scripts be run 
without approval so long as they limit themselves to operations considered inherently 
safe. This limited execution environment is called a sandbox. (Currently no sandbox 
implementations are available for other languages, so all such scripts must be approved if 
configured by non-administrators.)

To switch to this mode, simply check the box Use Groovy Sandbox below the Groovy script’s 
entry field. Sandboxed scripts can be run immediately by anyone. (Even administrators, 
though the script is subject to the same restrictions regardless of who wrote it.) When 
the script is run, every method call, object construction, and field access is checked 
against a whitelist of approved operations. If an unapproved operation is attempted, the 
script is killed and the corresponding Jenkins feature cannot be used yet.

The Script Security plugin ships with a small default whitelist, and integrating plugins 
may add operations to that list (typically methods specific to that plugin).

But you are not limited to the default whitelist: every time a script fails before running 
an operation that is not yet whitelisted, that operation is automatically added to another 
approval queue. An administrator can go to the same page described above for approval of 
entire scripts, and see a list of pending operation approvals. If Approve is clicked next 
to the signature of an operation, it is immediately added to the whitelist and available 
for sandboxed scripts.

Most signatures be of the form `method class.Name methodName arg1Type arg2Type…`, 
indicating a Java method call with a specific “receiver” class (this), method name, and 
list of argument (or parameter) types. (The most general signature of an attempted method 
call will be offered for approval, even when the actual object it was to be called on was 
of a more specific type overriding that method.) You may also see `staticMethod` for 
static (class) methods, `new` for constructors, and `field` for field accesses (get or 
set).

Administrators in security-sensitive environments should carefully consider which 
operations to whitelist. Operations which change state of persisted objects (such as 
Jenkins jobs) should generally be denied. Most `getSomething` methods are harmless.

### ACL-aware methods
Be aware however that even some “getter” methods are designed to check specific 
permissions (using an ACL: access control list), whereas scripts are often run by a system 
pseudo-user to whom all permissions are granted. So for example` method 
hudson.model.AbstractItem getParent` (which obtains the folder or Jenkins root containing 
a job) is in and of itself harmless, but the possible follow-up call `method 
hudson.model.ItemGroup getItems` (which lists jobs by name within a folder) checks 
Job/Read. This second call would be dangerous to whitelist unconditionally, since it would 
mean that a user who is granted Job/Create in a folder would be able to read at least some 
information from any jobs in that folder, even those which are supposed to be hidden 
according to a project-based authorization strategy; it would suffice to create a job in 
the folder which includes a Groovy script like this (details would vary according to the 
integrating plugin):

``` println("I sniffed ${thisjob.getParent().getItems()}!"); ```

When run, the script output would display at least the names of supposedly secret 
projects. An administrator may instead click Approve assuming permission check for 
`getItems`; this will permit the call when run as an actual user (if the integrating 
plugin ever does so), while forbidding it when run as the system user (which is more 
typical). In this case, `getItems` is actually implemented to return only those jobs which 
the current user has access to, so if run in the former case (as a specific user), the 
description will show just those jobs they could see anyway. This more advanced button is 
shown only for method calls (and constructors), and should be used only where you know 
that Jenkins is doing a permission check.

## Developer’s guide
[Complete example 
integration](https://github.com/jenkinsci/groovy-postbuild-plugin/pull/11/files)

### The easy way
For a typical Groovy integration, in which you offer the user the option of using either 
script approval or the sandbox, change your describable’s String-valued script field into 
a SecureGroovyScript field. In your constructor, before storing the value, call 
`configuringWithKeyItem` (if there could only be one such script per top-level item) or 
configuringWithNonKeyItem (if there might be several). The configuration form should use 
`<f:property field="…"/>` to pick up the script and sandbox configuration. When you want 
to run the script, just call evaluate.

(For compatibility with old data, pick a different field name and deprecate the original. 
Then you can define a readResolve method which sets the new field to a SecureGroovyScript 
with the sandbox off, calls `configuring(ApprovalContext.create())` on it to notify the 
system that an unapproved script has been loaded, and unsets the old field.)

### The hard way
To be used if you need more control than SecureGroovyScript offers:

Introduce a boolean sandbox field into your configuration.

When unset, you need to call` ScriptApproval.configuring` in the `@DataBoundConstructor`. 
Use `ApprovalContext.withCurrentUser`, and also `withItemAsKey` where applicable (when 
there is just one script per job); otherwise at least withItem where applicable, and/or 
`withKey` when you can uniquely identify this usage from the context 
(`StaplerRequest.findAncestorObject` is helpful here). This lets the system know a 
(possibly) new script has been configured by a particular person. You will also need a 
`readResolve` that calls configuring to notify the system when a configurable with script 
has been loaded from disk (and thus the configurer is unknown). Call 
`ScriptApproval.using` when the script is run, and catch `UnapprovedUsageException` if 
necessary. The descriptor should use form validation on the script field and call 
`ScriptApproval.checking` (generally your descriptor should already be doing at least a 
syntax check on this field).

When the sandbox field is set, you need merely set up the Groovy shell with 
`GroovySandbox.createSecureCompilerConfiguration` and then call `GroovySandbox.run`; be 
prepared to catch `RejectedAccessException` and call `ScriptApproval.accessRejected`.

### Preapproved methods for the sandbox
To preapprove some particular method calls, simply annotate them with @Whitelisted if in 
your plugin; otherwise you can register (with `@Extension`) a ProxyWhitelist delegating to 
StaticWhitelist.from and loading a text file listing whitelisted methods.

### Classpath for evaluating scripts
When constructing a GroovyShell to evaluate a script, or calling 
`ecureGroovyScript.evaluate`, you must pass a `ClassLoader` which represents the effective 
classpath for the script. You could use the loader of Jenkins core, or your plugin, or 
`Jenkins.getInstance().getPluginManager().uberClassLoader`.

Whatever you choose, do not allow an unprivileged user to add arbitrary classpath entries 
by making a `URLClassLoader`! This would make it trivial to bypass all security when using 
the sandbox. (A user need merely make this or another job archive a JAR containing some 
class with a static method marked `@Whitelisted` and doing whatever they like, then call 
the method from their script.) No attack has yet been demonstrated when using whole-script 
approval—a `URLClassLoader` with normal parent-first delegation would not permit trivial 
masking of innocent-looking APIs by compromised versions—but it is likely that some clever 
use of `META-INF/services/org.codehaus.groovy.transform.ASTTransformation` or similar 
could cause an otherwise safe script to behave in an unexpected and unauthorized manner. 
[JENKINS-22834](https://issues.jenkins-ci.org/browse/JENKINS-22834) suggests a safe 
standard alternative.

### Unit tests
When writing tests for plug-ins that use the Script Security Plugin you may encounter some 
errors in your tests.

If your tests call, direct or indirectly, the `ScriptApproval.get()` method, then your 
unit tests must use JenkinsRule so that `Jenkins.getInstance()` does not return null. It 
is likely that tests that were working now start to fail if you are not using the sandbox. 
It occurs because they are being enqueued for approval. In case you need to execute 
scripts regardless of approvals, `ScriptApproval.get().preapprove(script, 
GroovyLanguage.get())` will ensure that all configured scripts are approved. Alternately, 
you can have your tests run scripts using the sandbox. In this case you may need to 
whitelist methods used by your tests -- either generally for real users, or using a 
`@TestExtension` to have a whitelist just for tests.


## Version history
See [the changelog](CHANGELOG.md)
