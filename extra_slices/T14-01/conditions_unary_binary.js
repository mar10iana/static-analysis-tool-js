a = src1();
b = src2();
cond = true || b == !a;
if (cond) {
    sink();
} else {
    a = sanitize(a);
}
calc = (-a + b) * 3 > 1;
call(calc && !sanitize(cond) && (c || !a));
