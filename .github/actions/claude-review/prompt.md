Perform a comprehensive code review geared towards expert developers; be very concise and constructive.
If the file exists, also consider the additional context in `.github/copilot-instructions.md`.
These are the main focus areas for your review:

1. **Code Quality**
   - Clean code principles and best practices
   - DRY (Don't Repeat Yourself) adherence, including refactoring opportunities
     and usage of existing helper crate functionality and patterns to reduce boilerplate code
   - Idiomatic usage of all programming languages
   - Proper error and edge case handling
   - Code readability and maintainability
   - Flag changes to public APIs in shared crates that may break downstream consumers or browser integration

2. **Security**
   - Scrutinize any `unsafe` blocks, especially FFI boundaries — verify soundness,
     lifetime correctness, and null-pointer handling
   - Check for potential security vulnerabilities
   - Review untrusted input parsing and buffer handling for correctness and panic-safety
   - Check cryptographic correctness and TLS state machine safety
   - Consider protocol-level attacks (amplification, injection, timing)

3. **Performance**
   - Identify potential performance bottlenecks and optimizations
   - Check for memory leaks or resource and locking issues
   - Check for inefficient algorithms or data structures, suggest alternatives
   - Review memory allocations and deallocations, identify opportunities to eliminate them
   - Suggest the addition of benchmarks for new critical code paths

4. **Testing**
   - Verify adequate test coverage
   - Review test quality and edge cases
   - Check for missing test scenarios
   - When suggesting test additions, use existing test helpers or propose refactoring

5. **Documentation**
   - Ensure code is sufficiently - but not overly! - documented; the developers here are experts
   - Check whether comments and documentation related to changed code are updated and accurate
   - Verify README updates for new or changed features
   - Check API documentation accuracy

6. **Miscellaneous**
   - For changes to code that implements a technical specification (e.g., an IETF or W3C protocol,
     algorithm or other mechanism), verify that the changes implement the specification correctly.
     For any issues identified, include a link to the relevant section(s) of the specifications(s).
   - Verify correct use of feature gates — new code should not depend on CI-only or
     integration-only features at runtime

Before posting new comments, check any existing review comments from previous runs on this PR.
For each previous comment, determine whether the issue it raised is still present in the current code.
If it has been resolved, reply to that comment thread noting that the issue has been addressed, rather
than re-raising it. If it has been addressed, you may close ("resolve") the comment.

When encountering comments from other reviewers (including other AI agents) and you have differing
opinions on the points raised, succinctly comment on those as part of the review.

Whenever possible:

- Provide feedback using inline comments for specific issues; be concise
- Use GitHub suggestions in the comments. Include multiple GitHub suggestions
  whenever offering alternative fixes
- Begin each inline comment with a GitHub alert indicating importance:
  - `> [!CAUTION]` — blocking issue (correctness, security)
  - `> [!WARNING]` — should fix, but not blocking
  - `> [!NOTE]` — minor suggestion or nitpick
  - `> [!TIP]` — optional improvement

Use a top-level comment to summarize the changes in the reviewed PR and for general
observations or praise. The top-level comment is also where you should discuss any
architectural considerations for a PR, such as if simpler alternatives exist. Be concise.
