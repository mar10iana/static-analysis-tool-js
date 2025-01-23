a = src1();
b = src2();
c = "";
do {
   c = c + f;
   i = sink();
   f = sanitize(b);
} while (i == a);
sink(sanitize(c));
