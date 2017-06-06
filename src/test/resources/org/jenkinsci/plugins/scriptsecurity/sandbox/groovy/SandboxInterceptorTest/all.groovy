// A script that should exercise all keywords and operators.
// TODO:
// ===
// !==
// ||=
// &&=
// \
// \=
// native
// KEYWORD_DEFMACRO
// mixin
// KEYWORD_IMPORT
// KEYWORD_DO

package test

def fun() {
  return [];
}

arr = fun();
assert arr.collect { it -> it } == [];
arr << 0;
assert arr == [0];

assert true in [true, false];
(1..3).each {};
[1..3]*.toString();

assert 42 as String == "42"
assert 0 == [1:0][1];

assert "asdf" =~ /sd/
assert "asdf" ==~ /asdf/
assert ~/asdf/ instanceof java.util.regex.Pattern
assert 'asdf'[0..2] == 'asd'

assert 1 < 2 && 1 <= 2
assert 2 > 1 && 2 >= 1
assert 1 <=> 1 == 0
assert false || !false

assert (6 / 3 + 4) * (2 ** 3 - (3 % 2)) == 42

int a = 1
a += 1
a *= 2
a **= 2
a /= 2
a %= 5
assert a == 3

l = 1;
r = 3;
assert ++l-- == --r++;
assert +0 == -0

assert (2 << 1) + (8 >> 1) == (16 >>> 1);

def b = 8;
b >>= 1;
b >>>= 1;
b <<= 2;
assert b == 8;

assert !(false ? true : false)
assert false?:true;
assert null?.hashCode() == null

assert (1 | 2) == (1 & 3) + (1 ^ 3);

int bin = 15;
bin ^= 5;
bin |= 3;
bin &= 6;
assert bin == 2;

interface I {}

abstract strictfp class A implements I {
    final transient int v = 42;
    volatile double a;
    long l;
    float f;
    char ch;
    {}
    static {}
    protected static synchronized byte s() throws IOException {}
    public abstract void f();
    private short p() {};
    def d(String... s) { return 0 };
}

class E extends A {
    public void f() {
        def superP = super.&p;
        superP();
        def arr = ["Lorem", "ipsum"];
        this.d(*arr);
    }
    private int field;
}

assert new E() {} instanceof I;
new E().@field = 42;

if (false) {
    assert false;
} else {
    assert true;
}
label: for (i in [1, 2]) { continue label; }

switch (false) {
    case null: break;
    case true: break;
    default: break;
}

try {
    throw new Exception();
} catch (Exception _) {
} finally {
}
