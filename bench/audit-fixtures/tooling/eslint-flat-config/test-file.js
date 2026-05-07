// Trivial input ESLint will lint. The smoke check is "does ESLint LOAD
// the config and EXECUTE against this file" — the lint findings
// themselves are not asserted (we just need exit 0 or exit 1, not a
// crash with exit ≥ 2 from a config-load failure).
const x = 1;
console.log(x);
