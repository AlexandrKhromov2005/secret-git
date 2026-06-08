# RFC 8785 (JCS) reference test vectors

These `*.in.json` / `*.out.json` files are **external** test vectors taken verbatim from the
reference implementation project for RFC 8785 (JSON Canonicalization Scheme):

- Source: https://github.com/cyberphone/json-canonicalization (`testdata/input` and `testdata/output`)
- License: Apache License 2.0 (© the json-canonicalization authors)

They are used to validate `internal/manifest`'s canonical JSON encoder byte-for-byte against an
independent authority (see `jcs_rfc8785_test.go`), rather than against self-authored expectations.

Only the string-and-object vectors are within encgit's encoder domain (the manifest value space is
strings / uint64 / null / string-maps / string-arrays, no floats). `values.json` and `arrays.json`
contain floats / heterogeneous arrays and are used to assert that the encoder **fails explicitly**
on out-of-domain input instead of emitting wrong bytes.
