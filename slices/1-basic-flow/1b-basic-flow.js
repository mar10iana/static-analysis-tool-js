a = "";
a = b();
c = a;
d = c;
e(d);
c = "";

// tip: assignments propagate taintedness, and the order in which they are performed matters
