# Changelog

## Version 1.72

Release date: 2020-05-11

* This plugin now requires Jenkins 2.176.4 or newer.
* Improvement: Add various methods to the default whitelist: ([JENKINS-61952](https://issues.jenkins-ci.org/browse/JENKINS-61952), [PR 242](https://github.com/jenkinsci/script-security-plugin/pull/242), [PR 295](https://github.com/jenkinsci/script-security-plugin/pull/295), [PR 296](https://github.com/jenkinsci/script-security-plugin/pull/296))
    * Remaining `java.util.regex.Matcher` methods
    * Methods related to `java.time.Instant`
    * Methods and fields defined on `java.text.DateFormat`
    * Most methods defined on `java.text.Format`
    * Methods and fields defined on `java.util.Calendar`
    * `Boolean.booleanValue`
    * `Collection.containsAll(Collection)`
    * `List.indexOf(Object)`
    * Various extension methods defined in `DefaultGroovyMethods`
* Improvement: Make `SecureGroovyScript` and `ClasspathEntry` serializable so that they can be used by Active Choices Plugin. ([JENKINS-39742](https://issues.jenkins-ci.org/browse/JENKINS-39742))
* Fix: Clear static field signatures correctly when signature approvals are reset. ([PR 290](https://github.com/jenkinsci/script-security-plugin/pull/290))
* Internal: Update parent POM and minimum required Jenkins version to fix build errors when testing against new versions of Jenkins. ([PR 293](https://github.com/jenkinsci/script-security-plugin/pull/293))
* Internal: Update caffeine dependency to 2.8.2. ([PR 294](https://github.com/jenkinsci/script-security-plugin/pull/294))

## Version 1.71

Release date: 2020-03-09

* [Fix sandbox bypass vulnerability](https://jenkins.io/security/advisory/2020-03-09/#SECURITY-1754)

## Version 1.70

Release date: 2020-03-18

* [Fix sandbox bypass vulnerability](https://jenkins.io/security/advisory/2020-02-12/#SECURITY-1713)

## Version 1.69

Release date: 2020-01-27

* Improvement: Add various methods to the default whitelist: ([PR 280](https://github.com/jenkinsci/script-security-plugin/pull/280), [PR 281](https://github.com/jenkinsci/script-security-plugin/pull/281), [PR 283](https://github.com/jenkinsci/script-security-plugin/pull/283))
    * All remaining static methods in the `java.util.Collections` class
    * Groovy's `List.getAt(Collection)` extension method
    * Groovy's `List.transpose()` extension method
    * `Integer.parse(String, int)`
    * All of the fields in the `java.time.DayOfWeek` enum
* Internal: Add better logging for issues encountered in tests, update test-scope dependencies. ([PR 279](https://github.com/jenkinsci/script-security-plugin/pull/279), [PR 284](https://github.com/jenkinsci/script-security-plugin/pull/284))

## Version 1.68

Release date: 2019-11-21

* [Fix sandbox bypass vulnerability](https://jenkins.io/security/advisory/2019-11-21/#SECURITY-1658)

## Version 1.67

Release date: 2019-11-13

* Fix: Remove default whitelist entries that did not correspond to real signatures. ([PR 268](https://github.com/jenkinsci/script-security-plugin/pull/268))
* Improvement: Add the following signatures to the generic whitelist:
    * `Object[].getAt(IntRange)`
    * All remaining methods in the `java.util.regex` package
    * Getters/setters on `Date`
    * Various extension methods defined in `DateGroovyMethods`
* Internal: Migrate Wiki content to GitHub. ([PR 264](https://github.com/jenkinsci/script-security-plugin/pull/264))

## Version 1.66

Release date: 2019-10-01

* [JENKINS-59587](https://issues.jenkins-ci.org/browse/JENKINS-59587) - Fix issue that caused a cache used by the class loader for sandboxed Groovy scripts to be cleared out by the garbage collector when it should not have been. This could lead to performance issues for complex sandboxed scripts.

## Version 1.65

Release date: 2019-10-01

* [Fix sandbox bypass vulnerability](https://jenkins.io/security/advisory/2019-10-01/#SECURITY-1579)

## Version 1.64

Release date: 2019-09-13

*   [JENKINS-57563](https://issues.jenkins-ci.org/browse/JENKINS-57563) - Add support for configuring script approvals using [Jenkins Configuration as Code Plugin](https://plugins.jenkins.io/configuration-as-code).

## Version 1.63

Release date: 2019-09-12

*   [Fix sandbox bypass security vulnerabilities](https://jenkins.io/security/advisory/2019-09-12/#SECURITY-1538)

## Version 1.62

Release date: 2019-07-31

*   [Fix sandbox bypass security vulnerabilities](https://jenkins.io/security/advisory/2019-07-31/)

## Version 1.61

Release date: 2019-07-05

*   [JENKINS-56682](https://issues.jenkins-ci.org/browse/JENKINS-56682) - Fix the use of script-level initializers in sandboxed Groovy scripts, which was a regression from version 1.54.
*   [JENKINS-47430](https://issues.jenkins-ci.org/browse/JENKINS-47430) - Replace Guava cache used in for sandbox class loading with Caffeine to fix some performance issues and deadlocks.
*   Add the following methods to the generic whitelist:
    *   `Number.times(Closure)`
    *   `new PrintWriter(Writer)`
    *   `Reader.read()`
    *   `Reader.read(char[])`
    *   `Reader.read(char[], int, int)`
    *   `Reader.reset()`
    *   `Reader.skip(long)`
    *   `Writer.write(char[])`
    *   `Writer.write(char[], int, int)`
    *   `Writer.write(int)`
    *   `Writer.write(String)`
    *   `Writer.write(String, int, int)`
    *   `Appendable.append(char)`
    *   `Appendable.append(CharSequence)`
    *   `Appendable.append(CharSequence, int, int)`
    *   `AutoCloseable.close()`
    *   `Flushable.flush()`
    *   `new LinkedHashSet()`
    *   `List.add(int, Object)`
    *   `Matcher.find()`
    *   `DefaultGroovyMethods.getAt(Object[], Range)`
    *   `DefaultGroovyMethods.reverse(List)`

## Version 1.60

Release date: 2019-05-31

*   SandboxResolvingClassLoader.parentClassCache could leak loaders in a different way ([PR 253](https://github.com/jenkinsci/script-security-plugin/pull/253))

## Version 1.59

Release date: 2019-04-18

*   SandboxResolvingClassLoader.parentClassCache could leak loaders ([PR 252](https://github.com/jenkinsci/script-security-plugin/pull/252)) 
*   [JENKINS-57299](https://issues.jenkins-ci.org/browse/JENKINS-57299) - Add the following method to the generic whitelist:
    *   `DefaultGroovyMethods.drop(Iterable, int)`
    *   `DefaultGroovyMethods.drop(List, int)`
    *   `DefaultGroovyMethods.dropRight(Iterable, int)`
    *   `DefaultGroovyMethods.dropRight(List, int)`
    *   `DefaultGroovyMethods.take(List, int)`
    *   `DefaultGroovyMethods.takeRight(Iterable, int)`
    *   `DefaultGroovyMethods.takeRight(List, int)`

## Version 1.58

Release date: 2019-04-18

*   Always block `System.exit(int)` , `Runtime#halt(int)` , and `Runtime#exit(int)` 
*   [JENKINS-34973](https://issues.jenkins-ci.org/browse/JENKINS-34973) - Add script approvals from within `try/catch`  blocks.

## Version 1.57

Release date: 2019-04-11

*   Add the following methods to the generic whitelist:
    *   `Map.getOrDefault(Object, Object)`
    *   `Map.putIfAbsent(Object, Object)`
    *   `Map.replace(Object, Object)`
    *   `Map.replace(Object, Object, Object)`

## Version 1.56

Release date: 2019-03-25

*   [Fix security issue](https://jenkins.io/security/advisory/2019-03-25/#SECURITY-1353)

## Version 1.55

Release date: 2019-03-18

*   [JENKINS-55303](https://issues.jenkins-ci.org/browse/JENKINS-55303) - Internal: Update tests and test-scope dependencies so that the plugin can build with all tests passing on Java 11.

## Version 1.54

Release date: 2019-03-06

*   [Fix security issue](https://jenkins.io/security/advisory/2019-03-06/#SECURITY-1336%20(1))

## Version 1.53

Release date: 2019-02-19

*   [Fix security issue](https://jenkins.io/security/advisory/2019-02-19/#SECURITY-1320)

## Version 1.52

Release date: 2019-02-13

*   Add the following methods to the generic whitelist:
    *   `DateTimeFormatter.ofPattern(String)`
    *   `Iterable.take(int)`
    *   `List.subList(int, int)`

## Version 1.51

Release date: 2019-01-28

*   [Fix security issue](https://jenkins.io/security/advisory/2019-01-28/)

## Version 1.50

Release date: 2019-01-08

*   [Fix security vulnerability](https://jenkins.io/security/advisory/2019-01-08/)

## Version 1.49

Release date: 2018-11-30

*   Make sure expensive log lines are only created if the appropriate logging level is enabled ([PR #232](https://github.com/jenkinsci/script-security-plugin/pull/232))
*   Add the following methods to the generic whitelist:  

    *   `String#indexOf(int)`
    *   `String#indexOf(int, int)`
    *   `String#indexOf(String, int)`
    *   `String#lastIndexOf(int)`
    *   `String#lastIndexOf(int, int)`
    *   `String#lastIndexOf(String, int)`

## Version 1.48

Release date: 2018-10-29

*   [Fix security issue](https://jenkins.io/security/advisory/2018-10-29/)

## Version 1.47

Release date: 2018-10-17

*   Add the following methods to the generic whitelist:
    *   `DefaultGroovyMethods#leftShift(Writer, Object)`
    *   `Class#isInstance(Object)`
    *   `Throwable#getCause()`
    *   `Arrays#asList(Object[])`
    *   `Matcher#group(String)`
    *   `DefaultGroovyMethods#minus(List, Collection)`
    *   `DefaultGroovyMethods#asBoolean(CharSequence)`
    *   Various methods in the `java.time` package
*   Thanks, open source contributors TobiX, haridsv, kevinkjt2000!

## Version 1.46

Release date: 2018-09-05

*   [JENKINS-53420](https://issues.jenkins-ci.org/browse/JENKINS-53420) - Fix `MissingPropertyException` when executing Pipeline steps.

## Version 1.45

Release date: 2018-09-04

*   [JENKINS-50843](https://issues.jenkins-ci.org/browse/JENKINS-50843) - Allow calling `Closure` elements of a `Map` as methods.
*   [JENKINS-51332](https://issues.jenkins-ci.org/browse/JENKINS-51332) - Whitelist `Calendar` constants for days of the week and months (such as `MONDAY` and `APRIL`).
*   [JENKINS-50906](https://issues.jenkins-ci.org/browse/JENKINS-50906) - Allow `this.foo()` for closure variables.
*   Downgrade logging level for message about slow class loading increase threshold from 250ms to 1s.
*   Add the following methods to the generic whitelist:  

    *   `DefaultGroovyMethods#addAll(Collection, Object[])`
    *   `DefaultGroovyMethods#asImmutable(Map)`
    *   `DefaultGroovyMethods#flatten(List)`
    *   `DefaultGroovyMethods#getAt(List, Range)`
    *   `DefaultGroovyMethods#subMap(Map, Object[])`
    *   `DefaultGroovyMethods#subMap(Map, Collection)`

## Version 1.44

Release date: 2018-04-27

*   Add `DefaultGroovyMethods.toLong(String)` to the generic whitelist.
*   [JENKINS-50470](https://issues.jenkins-ci.org/browse/JENKINS-50470) - fix handling of `ArrayList.someField` to behave as a spread operation.
*   [JENKINS-46882](https://issues.jenkins-ci.org/browse/JENKINS-46882) - Add `new Exception(String)` to generic whitelist.

## Version 1.43

Release date: 2018-03-28

*   Add `DefaultGroovyMethods.collate` methods to the generic whitelist.
*   [JENKINS-50380](https://issues.jenkins-ci.org/browse/JENKINS-50380) - Stop going through `checkedCast` process for objects that can be assigned to the target class and just return them instead.
*   Add `Collection#remove(int)` and `List#remove(int)` to the generic whitelist.
*   Add `DefaultGroovyMethods` for `sort`, `toSorted`, `unique`, `max`, `min`, and `abs` to the generic whitelist. Note that using these (other than `abs`) in Pipeline code will not work until [JENKINS-44924](https://issues.jenkins-ci.org/browse/JENKINS-44924) is resolved.
*   Slightly improved error messages replacing `unclassified ...` for cases where we couldn't find a method, field, constructor, etc matching the signature.

## Version 1.42

Release date: 2018-03-12

*   [JENKINS-45982](https://issues.jenkins-ci.org/browse/JENKINS-45982) - Fix an issue with calling `super` for a CPS-transformed method.
*   [JENKINS-49542](https://issues.jenkins-ci.org/browse/JENKINS-49542) - add `Map#isEmpty()` to generic whitelist.
*   Add `DefaultGroovyMethods.multiply(String,Number)`, `DefaultGroovyMethods.with(Object,Closure)`, `Object#hashCode()`, `Objects.hash(Object[])`, `DefaultGroovyMethods.first(...)`, and `DefaultGroovyMethods.last(...)` to generic whitelist.

## Version 1.41

Release date: 2018-02-08

*   **Major improvement**: greatly reduce time required to check against static Whitelists
*   **Major improvement**: allow permission checks to multithread - elliminate lock contention with concurrent calls
*   Improve UX for clearing dangerous signatures [JENKINS-22660](https://issues.jenkins-ci.org/browse/JENKINS-22660)
*   Add Integer.toString(int, int) to default whitelist
*   Add DefaultGroovyMethods toListString and toMapString to whitelist

## Version 1.40

Release date: 2018-01-10

*   Block `System.getNanoTime()` to prevent Spectre/Meltdown exploits.
*   Add `DefaultGroovyMethods#contains(Iterable,Object)` to default whitelist.

## Version 1.39

Release date: 2017-12-12

*   [JENKINS-48501](https://issues.jenkins-ci.org/browse/JENKINS-48501) - Fix NPE regression caused by fix for JENKINS-48364 and JENKINS-46213.

## Version 1.38

Release date: 2017-12-11

*   [JENKINS-46764](https://issues.jenkins-ci.org/browse/JENKINS-46764) - Log useful message when `scriptApproval.xml` is malformed.
*   [JENKINS-48364](https://issues.jenkins-ci.org/browse/JENKINS-48364) - Treat null first vararg param properly.
*   [JENKINS-46213](https://issues.jenkins-ci.org/browse/JENKINS-46213) - Treat trailing array parameters as varargs when appropriate.

## Version 1.37

Release date: 2017-12-11

*   [Fix security issue](https://jenkins.io/security/advisory/2017-12-11/)

## Version 1.36

Release date: 2017-11-29

*   [JENKINS-47159](https://issues.jenkins-ci.org/browse/JENKINS-47159), [JENKINS-47893](https://issues.jenkins-ci.org/browse/JENKINS-47893) - Fix two issues with varargs handling.
*   Add more collection methods to the whitelist.
*   Hide `ScriptApproval` link if there are no pending or approved signatures.
*   Introduced support for `SystemCommandLanguage`

## Version 1.35

Release date: 2017-11-02

*   [JENKINS-47758](https://issues.jenkins-ci.org/browse/JENKINS-47758) -  New feature: plugins using the SecureGroovyScript.evaluate method are automatically protected against Groovy memory leaks (most plugins)  

    *   Notable plugin exceptions: email-ext, matrix-project, ontrack (may be covered by a later enhancement), job-dsl (needs a bespoke implementation) and splunk-devops plugins (can't cover - doesn't use enough script-security APIs)
    *   Pipeline offered its own leak protection mechanism (this is based on that)
*   [JENKINS-35294](https://issues.jenkins-ci.org/browse/JENKINS-35294) - VarArgs support for enums
*   Whitelist map.get method, List, minus, padLeft/padRight (thanks to community contributions from Github users [ryankillory](https://github.com/ryankillory), [Ignition](https://github.com/Ignition), and [andrey-fomin](https://github.com/andrey-fomin) !)
*   [JENKINS-47666](https://issues.jenkins-ci.org/browse/JENKINS-47666) - Add math.max and math.min to whitelist
*   [JENKINS-44557](https://issues.jenkins-ci.org/browse/JENKINS-44557) - Properly cast GString (Groovy dynamic/templated string) in varargs

## Version 1.34

Release date: 2017-09-05

*   [JENKINS-46391](https://issues.jenkins-ci.org/browse/JENKINS-46391) - Properly handle `~/foo/` regexp declarations and some other `Pattern` methods.
*   [JENKINS-46358](https://issues.jenkins-ci.org/browse/JENKINS-46358) - Whitelist a number of `StringGroovyMethods` including `replaceAll`, `findAll`, and more.

## Version 1.33

Release date: 2017-08-16

*   [JENKINS-46088](https://issues.jenkins-ci.org/browse/JENKINS-46088) Fix problems caused by double sandbox transformation of right-hand-side of declarations.
*   [JENKINS-33468](https://issues.jenkins-ci.org/browse/JENKINS-33468) Allow use of `it` implicit closure parameter.
*   [JENKINS-45776](https://issues.jenkins-ci.org/browse/JENKINS-45776) Better handling of scoping of closure local variables.
*   [JENKINS-46191](https://issues.jenkins-ci.org/browse/JENKINS-46191) Fix compilation of empty declarations, such as `String foo;`, in sandbox.

## Version 1.32

Release date: 2017-08-16

*   Failed release due to repository permissions issues; replaced by 1.33.

## Version 1.31

Release date: 2017-08-07

*   [Multiple security fixes](https://jenkins.io/security/advisory/2017-08-07/)

## Version 1.30

Release date: 2017-07-25

Now requires Jenkins 2.7.x or later, i.e., versions of Jenkins running Groovy 2.x.

*   Some whitelist and blacklist additions.
*   [JENKINS-42563](https://issues.jenkins-ci.org/browse/JENKINS-42563) Handling `super` calls to methods.

*   Be explicit about classpath directory rejection reason.
*   [JENKINS-45117](https://issues.jenkins-ci.org/browse/JENKINS-45117) Apply specificity comparisons to constructors, not just methods.

*   [JENKINS-37129](https://issues.jenkins-ci.org/browse/JENKINS-37129) Throw a more helpful `MissingMethodException` rather than an “unclassified” error.

*   Cleanup of math operations.
*   [JENKINS-34599](https://issues.jenkins-ci.org/browse/JENKINS-34599) Allow `final` fields to be set.

*   [JENKINS-45629](https://issues.jenkins-ci.org/browse/JENKINS-45629) Field initializers could produce a `NullPointerException` during script transformation.

## Version 1.29.1

Release date: 2017-07-10

*   [Fix security issue](https://jenkins.io/security/advisory/2017-07-10/)

## Version 1.29

Release date: 2017-06-15

*   Whitelist additions, particularly for `DefaultGroovyMethods`.

## Version 1.28

Release date: 2017-06-05

*   [JENKINS-34741](https://issues.jenkins-ci.org/browse/JENKINS-34741) Unclassified error when using Groovy struct constructors.

*   Default whitelist additions.

## Version 1.27

Release date: 2017-02-27

*   [JENKINS-41797](https://issues.jenkins-ci.org/browse/JENKINS-41797) Race condition could corrupt internal whitelist metadata.
*   [JENKINS-39159](https://issues.jenkins-ci.org/browse/JENKINS-39159) File handle leak when using custom script classpath could lead to unwanted locks on Windows or NFS.
*   Default whitelist additions.

## Version 1.26

Release date: 2017-02-13

*   Default whitelist additions.

## Version 1.25

Release date: 2017-01-03

*   More whitelist and blacklist entries.
*   Display a warning about previously approved signatures which are now in the blacklist.

## Version 1.24

Release date: 2016-10-20

*   [JENKINS-38908](https://issues.jenkins-ci.org/browse/JENKINS-38908) Improper handling of some varargs methods.
*   Various whitelist additions.

## Version 1.23

Release date: 2016-09-21

*   Better report [JENKINS-37599](https://issues.jenkins-ci.org/browse/JENKINS-37599), a bug in core tickled by the [Promoted Builds Plugin](https://wiki.jenkins.io/display/JENKINS/Promoted+Builds+Plugin).
*   A few new whitelist and blacklist entries.

## Version 1.22

Release date: 2016-08-15

*   Introduce a class loader caching layer for the Groovy sandbox to work around core performance limitations such as [JENKINS-23784](https://issues.jenkins-ci.org/browse/JENKINS-23784).
*   [JENKINS-37344](https://issues.jenkins-ci.org/browse/JENKINS-37344) Default whitelist additions pertaining to collections.

## Version 1.21

Release date: 2016-07-11

*   Default whitelist additions pertaining to build changelogs ([JENKINS-30412](https://issues.jenkins-ci.org/browse/JENKINS-30412)).

## Version 1.20

Release date: 2016-06-20

*   Various default whitelist additions.
*   [JENKINS-34739](https://issues.jenkins-ci.org/browse/JENKINS-34739) Support for varargs methods.
*   [JENKINS-33023](https://issues.jenkins-ci.org/browse/JENKINS-33023) `enum` initializer fixes.
*   Blacklisting `RunWrapper.getRawBuild`.

## Version 1.19

Release date: 2016-04-26

*   [JENKINS-24399](https://issues.jenkins-ci.org/browse/JENKINS-24399) Prohibit class directories from being approved classpath entries.
*   [JENKINS-33023](https://issues.jenkins-ci.org/browse/JENKINS-33023) Support `enum` initializers.
*   Permit metaclass methods to be run.
*   Some miscellaneous whitelist and blacklist additions.

## Version 1.18.1

Release date: 2016-04-11

*   Security release (CVE-2016-3102). [advisory](https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2016-04-11)

## Version 1.18

Release date: 2016-04-04

*   Groovy prefers a getter/setter to a field access, so act accordingly, particularly when suggesting signatures to approve.
*   [JENKINS-27725](https://issues.jenkins-ci.org/browse/JENKINS-27725) Various fixes to handling of GDK methods.
*   Some miscellaneous whitelist and blacklist additions.
*   [JENKINS-26481](https://issues.jenkins-ci.org/browse/JENKINS-26481) Supporting fix to GDK method handling necessary to support calls such as `Object.each(Closure)` from `groovy-cps` Pipeline.

## Version 1.17

Release date: 2016-01-25

*   `obj.prop` should interpret `boolean TheClass.isProp()`, not just `boolean TheClass.getProp()`.

## Version 1.16

Release date: 2016-01-19

*   Many more default whitelist entries, including standard Groovy operators and GDK methods.
*   [JENKINS-30432](https://issues.jenkins-ci.org/browse/JENKINS-30432) Warn about dangerous signatures.
*   [JENKINS-31234](https://issues.jenkins-ci.org/browse/JENKINS-31234) Groovy allows `Singleton.instance` as an alias for `Singleton.getInstance()`; handled.
*   [JENKINS-31701](https://issues.jenkins-ci.org/browse/JENKINS-31701) Misclassification of a method taking `long` and being passed an `int`.

## Version 1.15

Release date: 2015-08-20

*   Added a number of new default whitelist entries.
*   Properly classify pseudofields of a `Map`.
*   [JENKINS-29541](https://issues.jenkins-ci.org/browse/JENKINS-29541) Methods on a `GString` may really be called on a `String`.
*   Corrected classification of methods ambiguous between `GroovyDefaultMethods` and `invokeMethod`.
*   [JENKINS-28586](https://issues.jenkins-ci.org/browse/JENKINS-28586) Corrected handling of receivers inside a `Closure`.
*   [JENKINS-28154](https://issues.jenkins-ci.org/browse/JENKINS-28154) Fixing handling of Groovy operators.

## Version 1.14

Release date: 2015-04-22

*   Better error message when you mistype a method name on a Groovy class.
*   Default to using sandbox mode when the current user is not an administrator.

## Version 1.13

Release date: 2015-02-02

*   Testability fix only.

## Version 1.12

Release date: 2014-12-04

*   [JENKINS-25914](https://issues.jenkins-ci.org/browse/JENKINS-25914) Support for special whitelist of `env` in Workflow plugins.
*   Whitelisting `Collection.contains`.

## Version 1.11

Release date: 2014-12-03

*   Handling some more Groovy constructs, such as the `=~` operator, and GDK methods like `Iterable.join(String)`.

## Version 1.10

Release date: 2014-11-14

*   [JENKINS-25524](https://issues.jenkins-ci.org/browse/JENKINS-25524) Handle ambiguous method overloads better.

## Version 1.9

Release date: 2014-11-04

*   Code can escape sandbox if there are multiple copies of `groovy-sandbox.jar` in Jenkins ([JENKINS-25348](https://issues.jenkins-ci.org/browse/JENKINS-25348))

## Version 1.8

Release date: 2014-10-29

*   `groovy-sandbox` 1.8 has a few fixes.

## Version 1.7

Release date: 2014-10-13

*   [JENKINS-25118](https://issues.jenkins-ci.org/browse/JENKINS-25118) Handle methods with primitive arguments.

## Version 1.6

Release date: 2014-10-02

*   Handle `GroovyObject.invokeMethod(String,Object)` correctly during call site selecction.

## Version 1.5

Release date: 2014-08-19

*   [JENKINS-22834](https://issues.jenkins-ci.org/browse/JENKINS-22834) Added support for custom classpaths.

## Version 1.4

Release date: 2014-06-08

*   Do not bother enforcing whole-script approval when Jenkins is unsecured anyway.
*   Some changes to make writing acceptance tests easier.

## Version 1.3

Release date: 2014-05-13

*   Fixing some regressions from 1.2.

## Version 1.2

Release date: 2014-05-13

*   Updated Groovy sandbox library for better language coverage.

## Version 1.1

Release date: 2014-05-06

*   Making it possible to use Groovy functions with `def` syntax.
*   Added `GroovySandbox.run` to stop whitelists from being consulted on methods defined in the script itself.

## Version 1.0

Release date: 2014-04-15

*   String concatenation fix in sandbox.
*   Preapprove the empty script.
*   Support for static fields in sandbox.
*   Changed package of `AbstractWhitelist`.

## Version 1.0 beta 6

Release date: 2014-03-31

*   Added `SecureGroovyScript` convenience class.

## Version 1.0 beta 5

Release date: 2014-03-13

*   Fixed various bugs in the Groovy sandbox.
*   Added `AbstractWhitelist`.

## Version 1.0 beta 4

Release date: 2014-03-12

*   Refactored `Whitelist` to support `GString` and more

## Version 1.0 beta 3

Release date: 2014-03-01

*   Reverted GString fix for now

## Version 1.0 beta 2

Release date: 2014-02-28

*   @Whitelisted
*   initialization bug fix
*   Groovy GString fix

## Version 1.0 beta 1

Release date: 2014-02-28

*   Initial version.

