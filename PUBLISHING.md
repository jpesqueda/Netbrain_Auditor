# Publishing / Publicación

1. Run CI and validate with a real read-only NetBrain account. Do not upload generated reports.
2. Check whether the distribution name netbrain-auditor is available on both indexes.
3. Create a pending Trusted Publisher at https://test.pypi.org/manage/account/publishing/ with project name netbrain-auditor, owner jpesqueda, repository Netbrain_Auditor, workflow publish-testpypi.yml, environment testpypi.
4. In GitHub Actions, run Publish to TestPyPI on main. Install dependencies from PyPI separately, then install the test package:
   ```powershell
   py -m pip install rich PyYAML
   py -m pip install --index-url https://test.pypi.org/simple/ --no-deps netbrain-auditor==1.0.0
   netbrain-auditor --version
   netbrain-auditor --help
   ```
5. Repeat Trusted Publisher registration on https://pypi.org/manage/account/publishing/ using workflow publish-pypi.yml and environment pypi. Configure environment approval protection in GitHub if desired.
6. Run Publish to PyPI manually after testing. Install with `py -m pip install netbrain-auditor`. Published versions cannot be overwritten; increment the package and module version for corrections.

Existing PyPI projects require adding a publisher in the project settings instead of a pending publisher.
No API tokens are needed. See https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/.
