# Contributing during private development

RansomLab belongs to Antech-greyhat and is being developed for an educational
cybersecurity challenge. Read the [requirements](requirements.md),
[architecture](architecture.md) and [security boundaries](security.md)
before changing the application.

The owner currently requests **no commits**. Keep work uncommitted; do not push,
merge, create release tags or change repository visibility. A local feature
branch is not permission to publish. If the owner later authorizes commits,
follow the reviewed feature-branch, meaningful-prefix and review workflow.

## Engineering workflow

1. Identify the requirement, affected interfaces and observable acceptance cases.
2. Add meaningful failing tests for new behaviour, including negative/failure
   cases for safety, cryptography, persistence and recovery.
3. Implement a small cohesive change. Keep domain rules and safety checks in
   shared services rather than duplicating them in CLI, templates or scripts.
4. Run affected tests and relevant safety/recovery regressions. Record the exact
   environment and distinguish real-platform checks from mocks or RAM fixtures.
5. Request review with the problem, resulting behaviour, validation evidence,
   safety impact and remaining limitations. Resolve routine defects within the
   authorized work; do not reopen already accepted phase gates.

Use Python's standard library when practical. New packages, source changes,
unreviewed upgrades and implicit downloads require the project's dependency
review and installation authorization. Do not copy a custom cipher into the
project to avoid a dependency.

The current test entry point is:

```text
python -m unittest discover -s tests -v
```

Blocked native checks must remain visible and block unsupported release claims.
Do not remove a failing ancestor check, use a real personal file as a negative
test decoy, or add an environment flag that bypasses execution safeguards.

## Artifact hygiene

Never add credentials, API keys, run keys, dashboard tokens, actual malware,
personal documents, private incident data, runtime `.ransomlab` stores, VM images
or unreviewed browser traces to source control. Use generated synthetic fixtures
and reviewed small examples. Inspect diffs and artifacts before any future
authorized commit or distribution; deleting a secret later does not erase it
from history.

## License recommendation

MIT is a candidate license for the educational source because it is simple and
widely understood. This is a recommendation only: no license has been selected
or granted in this build. The owner must review licensing, third-party notices
and public release contents before publication. A permissive license is not a
technical control over downstream misuse; runtime boundaries remain essential.
