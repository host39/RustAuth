# Markdown Title Case

Use **title case** for all Markdown headings (`#` through `######`).

## Rules

- Capitalize major words (nouns, verbs, adjectives, adverbs).
- Lowercase short articles, conjunctions, and prepositions (`a`, `an`, `the`, `and`, `but`, `or`, `for`, `in`, `of`, `on`, `to`, `with`, `vs`) unless they are the first or last word.
- Capitalize both parts of hyphenated compounds (`End-to-End`, `Brute-Force Protection`).
- Keep acronyms, crate names, and package names as written (`ADR`, `HTTP`, `sqlx`, `rustauth-core`, `@rustauth/contracts`).
- **Counterexamples:** the BAD headings in the Examples section below are intentional. Do not "fix" them when applying this rule.

## Examples

```markdown
<!-- BAD -->
## Package map
### Sessions vs tokens
## Further reading

<!-- GOOD -->
## Package Map
### Sessions vs Tokens
## Further Reading
```

## Prose Style

No em-dashes in docs, code comments, or commit messages. Use a colon, a semicolon, parentheses, or a new sentence instead.
