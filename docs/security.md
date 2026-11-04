# Security boundaries and current limitations

RansomLab is an educational platform for generated disposable data. It must not
be used with production files, personal documents, real malware, credentials or
unrelated evidence. The owner authorized implementation across phases; that
does not waive the architecture's safety boundaries.

## Enforced application boundaries

- Fixed installed scenarios select registered fixture IDs. No public command
  accepts an arbitrary file-impact root, shell script, uploaded program or
  remote command string.
- Generated working copies are separate from clean copies, keys, manifests,
  state and evidence. The local manifest is bound to registry key material.
- Strict schemas, expiry/generation checks, bounded inputs and persistent
  duplicate-request handling constrain local scenario imports.
- A single mutation lease coordinates run, monitor, evidence and recovery work.
  Durable intents precede file writes; uncertain state requires reconciliation.
- Working writes use checked object access, and recovery success requires a
  complete trusted-baseline comparison. Invalid or unavailable boundaries fail
  closed.
- The dashboard is local and read-only, with token/session access controls,
  loopback/Host/Origin checks, escaped templates and bounded queries. It has no
  simulation or host-administration endpoints.

There is no spreading, persistence, stealth/evasion, security-tool disabling,
credential theft, unauthorized collection, exfiltration or general remote
execution. Platform helpers only print read-only prerequisite observations.

## What these controls do not prove

The [filesystem implementation](implementation/filesystem-boundary.md) documents
native Windows and Linux assumptions. Windows currently requires local NTFS and
opens every ancestor with no-follow semantics and retained sharing constraints.
The managed development token cannot open one required ancestor, so native
positive cases are blocked. This is a release limitation, not permission to
remove the check or run the application elevated.

The Linux adapter's held descriptors cannot stop a hostile same-user actor from
moving ancestor directories between checks. Dedicated account permissions,
supported filesystem testing and the documented trust model remain necessary.
No application can provide these guarantees against a malicious administrator,
compromised hypervisor, replaced executable or fully compromised process identity.

The runtime also rejects elevated or unverified process identities before
arming/file impact. This reduces authority but is not an OS sandbox. The VMware
manufacturer indicator is not remote attestation. Snapshot labels,
isolation and disposable-use confirmations are operator assertions; the program
does not independently verify the VMware configuration. The dashboard inventory
is declared, and it does not probe the network for machine status.

File writes and database commits are separate. Interrupted writes may leave
partial generated objects and pending intents; startup never automatically
resumes impact. Missing/deleted fixture objects are not recreated by the current
recovery workflow. Preserve available evidence and use the reviewed VM rollback
procedure when safe application recovery cannot complete.

Polling and simple count-based rules can miss transient changes and alert on
benign edits. The platform is not production endpoint protection. Containment
stops application scheduling; it does not isolate an operating system, disable
security products or terminate unrelated processes.

Evidence hashes support equality checks against a trusted comparison source.
Local manifests/databases and hash chains are not tamperproof. A partial evidence
bundle must retain its partial status. Public exports require review to exclude
keys, access tokens, private machine information and sensitive material.

Windows cryptography uses CNG; see the [provider review](implementation/crypto-provider.md).
Native vectors do not prove all guest builds, ABI combinations or future patch
levels safe. Python immutable copies prevent a guarantee of complete memory
zeroization. The optional non-Windows package fallback remains subject to exact
version/source/installation review.

## Reporting a problem during private development

Provide the owner a minimal synthetic reproducer, application/runtime versions,
expected and observed behaviour, relevant test names, and a redacted event
sequence. Do not include keys, real victim files or unrelated incident evidence.
There is no configured public security inbox or public issue tracker; do not
invent a destination or publish details before the owner chooses a process.

A boundary escape, arbitrary execution path, false verified-recovery result,
secret exposure or unsupported safety claim blocks the affected release scope.
Record failed and blocked tests explicitly instead of changing expected results
or quietly excluding the platform.
