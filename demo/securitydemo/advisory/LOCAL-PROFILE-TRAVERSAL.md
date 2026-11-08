# Local profile path traversal in Customer Portal

Related ranking signal: CVE-2026-22739 / GHSA-3qwq-q9vm-5j42

The Spring advisory covers unsafe profile substitution in Spring Cloud Config
Server's native filesystem backend. Customer Portal also ships a first-party
Python helper, `portal/config_loader.py`, that joins a caller-supplied profile
into a filesystem path without proving the result stays under `portal/configs`.

## Authoritative remediation evidence

1. Only profiles that resolve to a regular file inside `portal/configs` may be read.
2. Reject absolute paths, parent segments (`..`), null bytes, and any resolved
   path that is not inside the config root.
3. Keep legitimate profiles `default` and `prod` working.
4. Do not weaken or delete `portal/tests/test_config_loader.py`.
5. `python3 check_code_fix.py` must exit 0.
6. Do not invent a patched Maven version in this change set. Dependency pin work
   remains a separate pull request.

## Out of scope

- No exploit payload against a live Spring server
- No credentials in prompts or commits
- No merge or deploy
