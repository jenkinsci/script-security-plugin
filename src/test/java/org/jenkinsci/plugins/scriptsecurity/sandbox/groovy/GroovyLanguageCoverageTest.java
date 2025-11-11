package org.jenkinsci.plugins.scriptsecurity.sandbox.groovy;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.GenericWhitelist;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;

class GroovyLanguageCoverageTest {

    @Disabled("This fails on m.\"fruit${bKey}\" returning null due to JENKINS-46327")
    @Issue("JENKINS-46327")
    @Test
    void quotedIdentifiers() throws Exception {
        // See http://groovy-lang.org/syntax.html#_quoted_identifiers
        Whitelist whitelist = new GenericWhitelist();
        SandboxInterceptorTest.assertEvaluate(whitelist, true, """
                        def m = [fruitA: 'apple', fruitB: 'banana']
                        assert m.fruitA == 'apple'
                        assert m.'fruitA' == 'apple'
                        assert m."fruitA" == 'apple'
                        assert m.'''fruitA''' == 'apple'
                        assert m.""\"fruitA""\" == 'apple'
                        assert m./fruitA/ == 'apple'
                        assert m.$/fruitA/$ == 'apple'
                        def bKey = 'B'
                        assert m."fruit${bKey}" == 'banana'
                        assert m.""\"fruit${bKey}""\" == 'banana'\
                        assert m./fruit${bKey}/ == 'banana'
                        assert m.$/fruit${bKey}/$ == 'banana'
                        return true
                        """);
    }

    @Test
    void gStringWithClosure() throws Exception {
        // see http://groovy-lang.org/syntax.html#_special_case_of_interpolating_closure_expressions
        Whitelist whitelist = new GenericWhitelist();
        SandboxInterceptorTest.assertEvaluate(whitelist, true, """
                        def number = 1
                        def eagerGString = "value == ${number}"
                        def lazyGString = "value == ${ -> number }"
                        assert eagerGString == 'value == 1'
                        assert lazyGString.toString() == 'value == 1'
                        number = 2
                        assert eagerGString == 'value == 1'
                        assert lazyGString == 'value == 2'
                        return true
                        """);
    }

    @Test
    void arithmeticOperators() throws Exception {
        // see http://groovy-lang.org/operators.html#_arithmetic_operators
        Whitelist whitelist = new GenericWhitelist();
        SandboxInterceptorTest.assertEvaluate(whitelist, true, """
                        assert  1  + 2 == 3
                        assert  4  - 3 == 1
                        assert  3  * 5 == 15
                        assert  3  / 2 == 1.5
                        assert 10  % 3 == 1
                        assert  2 ** 3 == 8
                        assert +3 == 3
                        assert -4 == 0 - 4
                        assert -(-1) == 1 \s
                        def a = 2
                        def b = a++ * 3
                        assert a == 3 && b == 6
                        def c = 3
                        def d = c-- * 2
                        assert c == 2 && d == 6
                        def e = 1
                        def f = ++e + 3
                        assert e == 2 && f == 5
                        def g = 4
                        def h = --g + 1
                        assert g == 3 && h == 4
                        def a2 = 4
                        a2 += 3
                        assert a2 == 7
                        def b2 = 5
                        b2 -= 3
                        assert b2 == 2
                        def c2 = 5
                        c2 *= 3
                        assert c2 == 15
                        def d2 = 10
                        d2 /= 2
                        assert d2 == 5
                        def e2 = 10
                        e2 %= 3
                        assert e2 == 1
                        def f2 = 3
                        f2 **= 2
                        assert f2 == 9
                        return true
                        """);
    }

    @Test
    void bigDecimalOperators() throws Exception {
        // see http://groovy-lang.org/operators.html#_arithmetic_operators
        Whitelist whitelist = new GenericWhitelist();
        SandboxInterceptorTest.assertEvaluate(whitelist, true, """
                        assert  1.0  + 2.0 == 3.0
                        assert  4.0  - 3.0 == 1.0
                        assert  3.0  * 5.0 == 15.0
                        assert  3.0  / 2.0 == 1.5
                        assert  2.0 ** 3.0 == 8.0
                        assert +3.0 == 3.0
                        assert -4.0 == 0 - 4.0
                        assert -(-1.0) == 1.0
                        def a = 2.0
                        def b = a++ * 3.0
                        assert a == 3.0 && b == 6.0
                        def c = 3.0
                        def d = c-- * 2.0
                        assert c == 2.0 && d == 6.0
                        def e = 1.0
                        def f = ++e + 3.0
                        assert e == 2.0 && f == 5.0
                        def g = 4.0
                        def h = --g + 1.0
                        assert g == 3.0 && h == 4.0
                        def a2 = 4.0
                        a2 += 3.0
                        assert a2 == 7.0
                        def b2 = 5.0
                        b2 -= 3.0
                        assert b2 == 2.0
                        def c2 = 5.0
                        c2 *= 3.0
                        assert c2 == 15.0
                        def d2 = 10.0
                        d2 /= 2.0
                        assert d2 == 5.0
                        def f2 = 3.0
                        f2 **= 2.0
                        assert f2 == 9.0
                        return true
                        """);
    }
}
