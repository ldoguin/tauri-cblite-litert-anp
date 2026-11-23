# ANP SDK test vectors

The JSON files in this directory are **unmodified copies** of test fixtures from
<https://github.com/agent-network-protocol/anp> (AgentConnect, the ANP reference SDK), directory `testdata/`, copied on 2026-11-13.
They are licensed under the Apache License 2.0 (copy in `LICENSE`), Copyright 2024 GaoWei Chang and ANP Open Source Community.

The file names are the repository paths with `/` replaced by `_`:

| Here | In the SDK repository |
|---|---|
| `direct_e2ee_p5_shared_vectors.json` | `testdata/direct_e2ee/p5_shared_vectors.json` |
| `direct_e2ee_p5_v2_wire_vectors.json` | `testdata/direct_e2ee/p5_v2_wire_vectors.json` |
| `authentication_security_vectors_v1.json` | `testdata/authentication/security_vectors_v1.json` |
| `authentication_authority_compatibility_v1.json` | `testdata/authentication/authority_compatibility_v1.json` |
| `authentication_legacy_compatibility_v1.json` | `testdata/authentication/legacy_compatibility_v1.json` |
| `group_e2ee_p6_v2_wire_vectors.json` | `testdata/group_e2ee/p6_v2_wire_vectors.json` (copied on 2026-11-15) |

They are used only by tests that check this project's code against another implementation's expected values.
