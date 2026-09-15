# UFM TOON contract

Synthetic fixtures: JSON input (`*.json`) and exact TOON output (`*.toon`).
Use GAF's template engine to render TOON.
No production encoder dependency.

## Contract

- Use `{"results": [...]}`. Keep the envelope fields shown in the JSON fixtures,
  including both summaries. Missing or nil envelope values become `null`;
  empty findings become `[]`.
- Preserve the `FindingData` JSON: nested fields, omission/null semantics
  and numeric types. Keep every finding and
  array order; do not aggregate or generate summary text.
- Keep `from_line` and optional `to_line` as supplied, including explicit null.
  Do not rename them or fill in a missing end line.
- Preserve numbers exactly or return a rendering error.

Follow [TOON spec 4.1](https://github.com/toon-format/spec/blob/d6db4b04303bdea132351ce45aed612311c850b2/SPEC.md):
use two-space indentation, comma delimiter, UTF-8 and LF separators. No BOM,
trailing spaces or final newline. Sort object keys recursively by UTF-8 byte
order before rendering; never sort arrays.

## Regenerate

From this directory, use the [@toon-format/cli](https://toonformat.dev/cli/).
Replace `sca` with the case to regenerate:

```bash
jq -S . sca.json | npx --yes @toon-format/cli@4.1.1 --encode -o /tmp/sca.toon
printf '%s' "$(< /tmp/sca.toon)" > /tmp/sca.toon
cmp sca.toon /tmp/sca.toon
```

The `printf` command removes the `@toon-format/cli`'s final newline.
For contract changes, copy `/tmp/sca.toon` to `sca.toon` and review the diff.

Use the `@toon-format/cli` only for fixtures. Integers outside JavaScript's
safe range need separate template renderer tests.
