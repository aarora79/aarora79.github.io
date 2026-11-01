"""Ask Z3 if the range check can disagree with the spec."""

from z3 import (
    And,
    Ints,
    Solver,
    sat,
)

a, b, c, d = Ints("a b c d")
octets_valid = And([And(0 <= x, x <= 255) for x in (a, b, c, d)])
address = a * 2**24 + b * 2**16 + c * 2**8 + d

# The spec: 172.16.0.0 to 172.31.255.255, written as one number range.
low = 172 * 2**24 + 16 * 2**16
high = 172 * 2**24 + 31 * 2**16 + 255 * 2**8 + 255
spec = And(low <= address, address <= high)

guards = {
    "as written (b <= 32)": And(a == 172, 16 <= b, b <= 32),
    "fixed (b <= 31)": And(a == 172, 16 <= b, b <= 31),
}
for name, guard in guards.items():
    solver = Solver()
    solver.add(octets_valid, guard != spec)  # any disagreement
    if solver.check() == sat:
        m = solver.model()
        found = ".".join(str(m.eval(x)) for x in (a, b, c, d))
        print(f"{name}: counterexample {found}")
    else:
        print(f"{name}: no counterexample in all 2**32 addresses")
