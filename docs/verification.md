# Execution record

A local dry run of suspicious-login using a fictional account and TEST-NET address. Connectors do not execute containment actions. The test suite is run separately.

- `python -m pytest -v --tb=short` — exit 0 (expected 0).
- `soar run playbooks/suspicious-login.yaml --input account=demo.user --input source_ip=192.0.2.42 --input distance_km=6200` — exit 0 (expected 0).

The terminal image renders recorded command output. [Full transcript](screenshots/execution.txt).

External integrations and production deployment are not covered by these fixtures.
