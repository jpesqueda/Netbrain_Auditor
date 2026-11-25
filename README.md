# Netbrain Auditor

Read-only network inventory and data-quality audit for NetBrain. Version 1.0.0.

## English

Install after publication: `pip install netbrain-auditor`.

Run: `netbrain-auditor --url https://netbrain.example.local -u USERNAME --tenant LAB-TENANT --domain LAB-DOMAIN -o Network_Audit`.

Use `netbrain-auditor --help` for options. Password is prompted without echo. TLS verification is enabled by default. Reports reflect the selected domain and account permissions, not live device state.

## Español

Auditoría de inventario, antigüedad de descubrimiento, datos faltantes, duplicados y versiones. No modifica dispositivos ni inicia tareas de discovery. Los hallazgos son candidatos a revisión, no prueba de fallas físicas.

Ejemplo: `netbrain-auditor --url https://netbrain.example.local -u USERNAME -o Network_Audit`.

Modo sin conexión: `netbrain-auditor --from-json examples/devices.json -o Demo`.

Política opcional: `--software-policy examples/approved_versions.yaml`. Sin política, las versiones se inventarían sin emitir un veredicto de cumplimiento. Prefijos de modelos se comparan sin distinguir mayúsculas, con el prefijo más largo primero; versiones exactas.

## Reports / Reportes

- Network_Inventory.csv: normalized inventory
- Audit_Findings.csv: one row per finding
- Software_Versions.csv: per-device version and compliance
- Software_Summary.csv: counts by vendor, model and version
- Stale_Devices.csv: devices older than the threshold
- Missing_Information.csv: missing or unusable fields, unassigned sites
- Duplicate_Devices.csv: possible duplicate management IP, hostname, serial
- Audit_Summary.csv: coverage and counts
- Network_Audit.log: diagnostics and elapsed time

Default stale threshold: 30 days. Unknown discovery times remain unknown. Reports may contain sensitive infrastructure data; do not commit or share them without sanitization. Existing output directories must be empty unless --overwrite is explicitly supplied. Successful collection is scoped to the account's visible inventory. No automatic publication until a maintainer configures trusted publishing.

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests
python -m pip install build twine
python -m build
python -m twine check dist/*
```

See PUBLISHING.md for TestPyPI and PyPI steps. All example data is synthetic.
