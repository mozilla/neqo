Rely on the context in `.github/copilot-instructions.md` about the overall project.
Perform a comprehensive code review with the following focus areas; be concise and constructive:

1. **Code Quality**
   - Clean code principles and best practices
   - DRY (Don't Repeat Yourself) adherence, including refactoring opportunities
     and usage of helper crate functionality and patterns
   - Idiomatic usage of programming languages
   - Proper error handling and edge cases
   - Code readability and maintainability

2. **Security**
   - Check for potential security vulnerabilities
   - Validate input sanitization
   - Review authentication/authorization logic

3. **Performance**
   - Identify potential performance bottlenecks and easy optimizations
   - Check for memory leaks or resource issues
   - Check for inefficient algorithms or data structures
   - Review memory allocations and deallocations
   - Suggest the addition of benchmarks for new critical code paths

4. **Testing**
   - Verify adequate test coverage
   - Review test quality and edge cases
   - Check for missing test scenarios

5. **Documentation**
   - Ensure code is properly - but not overly! - documented
   - Check whether comments related to changed code are updated and accurate
   - Verify README updates for new or changed features
   - Check API documentation accuracy

Whenever possible:

- Provide feedback using inline comments for specific issues
- Use GitHub suggestions in the comments

Use top-level comments for general observations or praise. Be concise.
