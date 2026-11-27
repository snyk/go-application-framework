# Brain

## File filter (`pkg/utils/file_filter*.go`)

- The file filter never follows or lists symlinks (files, folders, ignore files), independent of `FF_FILE_FILTER_GIT_SEMANTICS`. Reading a symlink can upload files from outside the scanned repo. Keep this unconditional; do not gate it behind the flag.
- `FF_FILE_FILTER_GIT_SEMANTICS` only gates the git-style behaviour: `.git` folders are skipped and negations cannot re-include files inside excluded folders.
- Symlink tests run with the flag on and off (`file_filter_symlink_test.go`); the reference filter in `file_filter_reference_test.go` drops symlinks in both states.
