-- An IPv4 address as one number, from its four octets.
def toNat (a b c d : Nat) : Nat :=
  a * 16777216 + b * 65536 + c * 256 + d

-- The spec: 172.16.0.0 through 172.31.255.255.
def inPrivate172 (n : Nat) : Prop :=
  2886729728 ≤ n ∧ n ≤ 2887778303

-- The guard's check, fixed to stop at 31.
def guard172 (a b : Nat) : Prop :=
  a = 172 ∧ 16 ≤ b ∧ b ≤ 31

theorem guard_matches_spec (a b c d : Nat)
    (ha : a < 256) (hb : b < 256) (hc : c < 256) (hd : d < 256) :
    guard172 a b ↔ inPrivate172 (toNat a b c d) := by
  unfold guard172 inPrivate172 toNat
  omega
