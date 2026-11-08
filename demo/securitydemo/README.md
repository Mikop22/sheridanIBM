# securitydemo

Sample Customer Portal used by the SignalZero judge demo.

## Dependency pin

`spring-cloud-config-server` is pinned in `pom.xml`. GitHub Advisory
GHSA-3qwq-q9vm-5j42 names 4.3.2 as the patched release on the 4.3 line.
`check_version.py` exits non-zero until that pin moves.

## First-party code finding

`portal/config_loader.py` joins a caller-supplied profile into a filesystem
path without proving the result stays under `portal/configs`. That reproduces
the same class of bug as the Spring native-backend advisory, in application
code the dependency bump does not remove.

- Evidence: `advisory/LOCAL-PROFILE-TRAVERSAL.md`
- Gate: `python3 check_code_fix.py` (runs `portal/tests`)
- Expected remediation: rewrite `resolve_config_path` so traversal, absolute
  paths, and null bytes are rejected while `default` and `prod` still load

This tree contains no exploit against a live server. The company inventory that
points here is synthetic.
