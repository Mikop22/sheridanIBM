# securitydemo

Sample Customer Portal pin for the SignalZero judge demo.

`spring-cloud-config-server` is pinned to 4.3.1. GitHub Advisory
GHSA-3qwq-q9vm-5j42 lists that 4.3 range as affected and names 4.3.2 as the
patched release on this line. `check_version.py` exits non-zero until the pin
is 4.3.2.

This tree contains no exploit. The company inventory that points here is synthetic.
The coding agent is expected to change only the dependency pin, on a branch, and
open a draft pull request.
