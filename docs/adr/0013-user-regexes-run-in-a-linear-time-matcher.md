# ADR 0013: User regular expressions run in a linear-time matcher

Status: Accepted (2026-11-25, owner decision; written by a contributor from the owner's decision, and
confirmed when the owner merges the pull request that adds it)

## Context

The query language lets operators filter Sessions, Logs, Policies and Objects with regular
expressions (`/.../flags` and `key~"..."`), run in the browser over at most the first 2,048
characters of each text ([Spec 004, section 9](../specs/004-live-sessions-and-logs.md#9-security-considerations)).
The browser's `RegExp` backtracks, so a pattern such as `(a+)+$` or `.*=.*=.*!` can take seconds on
one long line.

Until now a static check in `query.js` read each pattern and refused the shapes it believed were
slow: nested repeats, two repeats that can match the same text, repeated ambiguous choices and long
runs of optional parts. It was a heuristic, not a proof, and it had to re-implement the engine's
reading of every escape, class and flag to decide what overlaps. An adversarial hunt found 97
patterns that froze a tab for 0.2 to 12 s each. For 85 of them the check let the pattern through
and the engine took 0.2 to 10.6 s on one line (53 on lines of 1,000 to 2,048 characters, 32 on lines
of 11 to 81 characters); for the other 12 the check itself took 0.3 to 12 s to read a long pattern.
Most misses came from places where the check read the pattern differently from the engine: `\c`
without a letter, astral characters with and without `u`, legacy octal escapes, `\u{...}` with
leading zeros, quantifier numbers with many digits, case folding under `i` and `iu`, and `\p{...}`
sampled on a few characters. Each fix would have left the next miss.

The harm is a self-inflicted denial of service: the operator's own tab stops responding, through a
filter they typed or a crafted link that carries a query. No pattern reaches the device or the
daemon, so this is not a risk to the routing engine or the server. Logs already stops a refilter
after a time budget; Sessions, Policies and Objects had no time box and relied on the check.

## Decision

1. **Every user pattern runs in J-Wicket's own NFA** ([`regexvm.js`](../../src/jwicket/static/js/regexvm.js)),
   a Thompson construction simulated as a Pike VM: all threads advance one character at a time, and
   each state is visited at most once per position. Testing one line costs at most
   (line length + 1) times the pattern's NFA states, so no pattern can backtrack exponentially or
   polynomially. The browser's `RegExp` never runs a user pattern as a whole.
2. **Character-level semantics are the browser's own.** Each single-character atom (a literal, a
   class, an escape or `.`) is compiled to a native `^(?:atom)$` with the flags in effect at that
   point and tested on one code unit (without `u`) or one code point (with `u`). So case folding
   under `i` and `iu`, `\p{...}`, dotAll, multiline anchors and `\b` under `iu` match the browser
   exactly. The NFA handles the structure: concatenation, alternation, groups, quantifiers, `^`, `$`,
   `\b` and `\B`. For every pattern the matcher accepts, its `.test()` gives the same boolean as the
   browser's `RegExp`.
3. **Lookaround and back-references are refused** with a plain message that says what was refused
   and what to write instead, as is anything the matcher's parser does not read exactly (it fails
   closed). Two places where V8 departs from the standard, `\B` inside a surrogate pair under `u`
   and case-insensitive branches that V8 merges by Unicode folding without `u`, are refused rather
   than imitated.
4. **The bounds stay.** Patterns are capped at 2,048 characters and `MAX_STATES` = 768 NFA states;
   texts at 2,048 characters (`REGEX_INPUT_MAX`); Logs keeps its refilter time budget (150 ms, and
   50 ms for the new lines of one read) as a second line of defence.

This replaces the static check and settles owner decision OD-11 of Spec 004, whose default was the
check plus the time budget.

## Consequences

- Lookahead, lookbehind and back-references, numbered or named, no longer work in a filter. Logs and
  policy names rarely need them; two terms (`a -b`) or a written-out repeat cover most uses. The
  query bar's help says what is supported and what is not.
- Shapes the check refused, such as `.*=.*zzz` or `(a|aa)+$`, now run, and quickly.
- One line's worst case is bounded by `MAX_STATES`: on the reference machine, the worst shapes found
  take about 10 to 27 ms on a 2,048-character line at 768 states. A larger budget would admit larger
  patterns at a higher cost per line; the tests (`regexvm.test.mjs`, "linear time") keep the worst
  shapes in view. Patterns that need more states are refused with a message to use smaller counts.
- The matcher is about a thousand lines of J-Wicket's own code that must track the engine's grammar,
  including Annex B quirks. It is tested by a differential test against the engine over random and
  exhaustive patterns, all 97 hunt patterns, and hand-written edge cases. That suite passes under
  Node 22 (V8 12.4) and, run in the page with small stand-ins for `node:test` and `node:assert`,
  in Chrome 158; the larger fuzzing beyond the suite was run against Node 22 only.
- No dependency, no `eval` or `new Function`, no new script loading: CSP and Trusted Types are
  unaffected. No Web Worker is needed.
- A filter over many rows still costs rows times one line's bound. Logs keeps its time budget for
  that reason; Sessions, Policies and Objects filter at most a few thousand short texts.

## What would prove it wrong

- A pattern the matcher accepts whose `.test()` answer differs from the browser's `RegExp` on some
  text: a correctness bug in the matcher, to fix there or to refuse.
- A pattern the matcher accepts that takes more than about 50 ms on one 2,048-character line in a
  supported browser: `MAX_STATES` is too high, or a step is not linear.
- Operators who need lookaround or back-references often enough that refusing them costs more than
  the risk it removes; the answer would then be a bounded native fallback, decided in a new ADR.
- A Chromium release whose character-level answers differ from V8 12.4's in a way the per-atom
  native test does not capture (for example a change in how `\b` or case folding works across
  atoms).
