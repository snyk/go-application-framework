# UFM TOON contract

Synthetic fixtures: UFM input (`*.testresult.json`), expected JSON (`*.json`)
and exact TOON output (`*.toon`). Use GAF's template engine to render TOON.
No production encoder dependency.

## Contract

- Use `{"results": [...]}`. Keep the envelope fields shown in the JSON fixtures,
  including both summaries. Prefer `Get(field)` where supported; use dedicated
  getters otherwise. Missing or nil envelope values become `null`; complete
  empty findings become `[]`.
- Read findings through `TestResult.Findings(ctx)` to restore stored problems.
  Return an error before writing if extraction fails or `complete == false`.
- Preserve the returned `FindingData` JSON: tags, custom marshalers, nested
  fields, omission/null semantics and numeric types. Keep every finding and
  array order; do not aggregate or generate summary text.
- Keep `from_line` and optional `to_line` as supplied, including explicit null.
  Do not rename them or fill in a missing end line.
- Preserve numbers exactly or return a rendering error.

Follow [TOON spec 4.1](https://github.com/toon-format/spec/blob/d6db4b04303bdea132351ce45aed612311c850b2/SPEC.md):
use two-space indentation, comma delimiter, UTF-8 and LF separators. No BOM,
trailing spaces or final newline. Sort object keys recursively by UTF-8 byte
order before rendering; never sort arrays.

## Verify

From the repository root:

```fish
go test ./internal/presenters -run '^Test_UfmTOONContract$' -count=1

set toon_reference (mktemp -d)
npm pack @toon-format/toon@4.1.1 --pack-destination "$toon_reference"
tar -xzf "$toon_reference/toon-format-toon-4.1.1.tgz" -C "$toon_reference"
node internal/presenters/testdata/ufm/toon/verify.mjs "$toon_reference/package/dist/index.mjs"
```

`@toon-format/toon@4.1.1` is only for generating and verifying fixtures.
The checks compare UFM extraction with expected JSON, exact TOON bytes and
strictly decoded JSON. Do not trim whitespace. The verifier rejects integers
outside JavaScript's safe range; cover those in the template renderer tests.

To regenerate, add `--write` to the Node command, review the diff and rerun both checks.
