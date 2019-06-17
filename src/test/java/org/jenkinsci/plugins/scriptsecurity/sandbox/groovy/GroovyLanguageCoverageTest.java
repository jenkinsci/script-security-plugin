package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.GenericWhitelist;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.jvnet.hudson.test.Issue;

public class GroovyLanguageCoverageTest {

    @Rule
    public ErrorCollector errors = new ErrorCollector();

    private void assertEvaluate(Whitelist whitelist, Object expected, String script) {
        SandboxInterceptorTest.assertEvaluate(whitelist, expected, script, errors);
    }

    @Ignore("This fails on m.\"fruit${bKey}\" returning null due to JENKINS-46327")
    @Issue("JENKINS-46327")
    @Test
    public void quotedIdentifiers() throws Exception {
        // See http://groovy-lang.org/syntax.html#_quoted_identifiers
        assertEvaluate(new GenericWhitelist(),
                true,
                "def m = [fruitA: 'apple', fruitB: 'banana']\n" +
                        "assert m.fruitA == 'apple'\n" +
                        "assert m.'fruitA' == 'apple'\n" +
                        "assert m.\"fruitA\" == 'apple'\n" +
                        "assert m.'''fruitA''' == 'apple'\n" +
                        "assert m.\"\"\"fruitA\"\"\" == 'apple'\n" +
                        "assert m./fruitA/ == 'apple'\n" +
                        "assert m.$/fruitA/$ == 'apple'\n" +
                        "def bKey = 'B'\n" +
                        "assert m.\"fruit${bKey}\" == 'banana'\n" +
                        "assert m.\"\"\"fruit${bKey}\"\"\" == 'banana'" +
                        "assert m./fruit${bKey}/ == 'banana'\n" +
                        "assert m.$/fruit${bKey}/$ == 'banana'\n" +
                        "return true\n"
        );
    }

    @Test
    public void gStringWithClosure() throws Exception {
        // see http://groovy-lang.org/syntax.html#_special_case_of_interpolating_closure_expressions
        assertEvaluate(new GenericWhitelist(),
                true,
                "def number = 1\n" +
                        "def eagerGString = \"value == ${number}\"\n" +
                        "def lazyGString = \"value == ${ -> number }\"\n" +
                        "assert eagerGString == 'value == 1'\n" +
                        "assert lazyGString.toString() == 'value == 1'\n" +
                        "number = 2\n" +
                        "assert eagerGString == 'value == 1'\n" +
                        "assert lazyGString == 'value == 2'\n" +
                        "return true\n"
        );
    }

    @Test
    public void arithmeticOperators() throws Exception {
        // see http://groovy-lang.org/operators.html#_arithmetic_operators
        assertEvaluate(new GenericWhitelist(),
                true,
                "assert  1  + 2 == 3\n" +
                        "assert  4  - 3 == 1\n" +
                        "assert  3  * 5 == 15\n" +
                        "assert  3  / 2 == 1.5\n" +
                        "assert 10  % 3 == 1\n" +
                        "assert  2 ** 3 == 8\n" +
                        "assert +3 == 3\n" +
                        "assert -4 == 0 - 4\n" +
                        "assert -(-1) == 1  \n" +
                        "def a = 2\n" +
                        "def b = a++ * 3\n" +
                        "assert a == 3 && b == 6\n" +
                        "def c = 3\n" +
                        "def d = c-- * 2\n" +
                        "assert c == 2 && d == 6\n" +
                        "def e = 1\n" +
                        "def f = ++e + 3\n" +
                        "assert e == 2 && f == 5\n" +
                        "def g = 4\n" +
                        "def h = --g + 1\n" +
                        "assert g == 3 && h == 4\n" +
                        "def a2 = 4\n" +
                        "a2 += 3\n" +
                        "assert a2 == 7\n" +
                        "def b2 = 5\n" +
                        "b2 -= 3\n" +
                        "assert b2 == 2\n" +
                        "def c2 = 5\n" +
                        "c2 *= 3\n" +
                        "assert c2 == 15\n" +
                        "def d2 = 10\n" +
                        "d2 /= 2\n" +
                        "assert d2 == 5\n" +
                        "def e2 = 10\n" +
                        "e2 %= 3\n" +
                        "assert e2 == 1\n" +
                        "def f2 = 3\n" +
                        "f2 **= 2\n" +
                        "assert f2 == 9\n" +
                        "return true\n"
        );
    }

    @Test
    public void bigDecimalOperators() throws Exception {
        // see http://groovy-lang.org/operators.html#_arithmetic_operators
        assertEvaluate(new GenericWhitelist(),
                true,
                "assert  1.0  + 2.0 == 3.0\n" +
                        "assert  4.0  - 3.0 == 1.0\n" +
                        "assert  3.0  * 5.0 == 15.0\n" +
                        "assert  3.0  / 2.0 == 1.5\n" +
                        "assert  2.0 ** 3.0 == 8.0\n" +
                        "assert +3.0 == 3.0\n" +
                        "assert -4.0 == 0 - 4.0\n" +
                        "assert -(-1.0) == 1.0\n" +
                        "def a = 2.0\n" +
                        "def b = a++ * 3.0\n" +
                        "assert a == 3.0 && b == 6.0\n" +
                        "def c = 3.0\n" +
                        "def d = c-- * 2.0\n" +
                        "assert c == 2.0 && d == 6.0\n" +
                        "def e = 1.0\n" +
                        "def f = ++e + 3.0\n" +
                        "assert e == 2.0 && f == 5.0\n" +
                        "def g = 4.0\n" +
                        "def h = --g + 1.0\n" +
                        "assert g == 3.0 && h == 4.0\n" +
                        "def a2 = 4.0\n" +
                        "a2 += 3.0\n" +
                        "assert a2 == 7.0\n" +
                        "def b2 = 5.0\n" +
                        "b2 -= 3.0\n" +
                        "assert b2 == 2.0\n" +
                        "def c2 = 5.0\n" +
                        "c2 *= 3.0\n" +
                        "assert c2 == 15.0\n" +
                        "def d2 = 10.0\n" +
                        "d2 /= 2.0\n" +
                        "assert d2 == 5.0\n" +
                        "def f2 = 3.0\n" +
                        "f2 **= 2.0\n" +
                        "assert f2 == 9.0\n" +
                        "return true\n"
        );
    }
}
