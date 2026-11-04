# Filesystem boundary implementation

The internal adapter is `ransomlab/storage.py`. It is not a provenance registry,
an OS sandbox, or a public directory-encryption interface. Application services
must authorize generated fixture IDs, enforce their smaller workload limits,
preserve verified clean copies, acquire a mutation lease and record durable
intent before calling a write operation.

## API contract

`SafeDirectory(absolute_path, create=False)` opens and holds a directory until
closed. The supplied path is an application-owned location, never scenario
input. `create=True` requires an absent final directory and existing parents;
it must not adopt an existing directory as newly generated.

- `create(name, bytes)` uses exclusive creation and never overwrites a file.
- `read(name, max_bytes)` bounds the read and rejects changing metadata.
- `identity(name)` returns the filesystem device and object identifier.
- `exists(name)` returns false only for a missing object; an unsafe object is
  an error, not an absent file.
- `names()` checks every flat entry and rejects unexpected names, links and
  directories. Services must compare this inventory to the fixture registry.
- `replace(name, bytes, expected=identity)` writes through the same checked
  handle. It never opens a second pathname for replacement. Callers should
  always supply their registered identity.
- `pin(name)` holds an existing regular object's identity while a repository
  uses it. On Windows this allows SQLite reads/writes but denies deletion or
  replacement. It does not authenticate the bytes. Pin existing SQLite
  `state.db-journal`, `state.db-wal` and `state.db-shm` sidecars as well as the
  main file only when the selected journal lifecycle permits retaining those
  handles. SQLite DELETE-journal cleanup cannot delete a pinned sidecar; the
  initial service should reject unexpected existing sidecars and require
  reviewed recovery rather than silently opening through them.

Internal names are ASCII basenames of 1–128 characters followed by `.bin`,
`.json`, `.key`, `.flag`, `.txt`, `.db`, or the exact SQLite sidecar suffixes.
Reserved Windows device basenames are rejected on every platform. Database,
key and metadata names must never enter the service's impact fixture inventory.
The adapter's absolute object ceiling is 64 MiB; this does not supersede the
service's smaller fixture, event, evidence and database limits.

`LabLease(path)` requires the exact basename `lease.flag` and acquires a
nonblocking one-byte Windows lock or a POSIX advisory lock. It retains the
lease file after unlocking; unlink/recreate lock races are avoided. The lease
serializes cooperating application operations, not hostile same-user programs.

## Windows contract

The initial Windows implementation requires a local fixed NTFS volume.
UNC/network, device, extended-length and drive-relative paths are rejected.
Unsafe component aliases, colon/stream syntax, reparse points, junctions,
directory objects in file positions and multiply linked files are rejected.

Every directory ancestor is opened with `CreateFileW`, backup semantics and
`FILE_FLAG_OPEN_REPARSE_POINT`. Retained handles deny write and delete sharing.
This prevents cooperating filesystem opens from replacing/renaming those
directory objects or opening them to change reparse data during an operation.
The adapter inspects attributes and identities through held handles. Failure
to open or verify any ancestor stops the operation; there is no fallback to
string-only path validation.

Normal files are opened with no write/delete sharing, inspected as disk files
with one hard link on the expected volume, and then read or written through
that handle. Pin handles are the limited exception: they permit writes but
still deny delete sharing so SQLite can operate. This is not protection from
an administrator, a compromised process identity, raw volume access or actors
able to alter the executable/trust material.

## Linux contract

The adapter uses held directory descriptors, `O_DIRECTORY`, `O_NOFOLLOW`,
descriptor-relative file opens and device/inode checks. It rejects unsupported
or network filesystem types according to `/proc/self/mountinfo`; the current
local candidates are ext4, XFS, Btrfs, tmpfs and overlay. Candidate support is
not a claim of tested release support.

Before and after operations, it checks that each named ancestor still matches
the held object. Holding a directory descriptor does **not** prevent a hostile
same-user process from moving that directory. Such an actor can create a race
between the check and operation; the adapter does not claim to solve it with
path checks. Dedicated account permissions and a disposable environment remain
required, and Linux impact functionality must not be released as validated
without its platform review and adversarial tests. Privileged mount changes
also invalidate the supported-environment assumptions.

## Writes, crashes and permissions

Replacing a working copy writes and truncates the same file handle, then
flushes it. This avoids a pathname rename race but is intentionally not an
atomic write. A crash may leave partial or old trailing data. A durable pending
intent must survive, and reconciliation plus clean-copy restoration must be
available before additional impact operations. The adapter never automatically
deletes uncertain partial files or resumes writes.

New Linux directories/files request 0700/0600 permissions. Windows directories
and files inherit the approved parent's ACL; this module does not provision a
restricted account or prove that its inherited ACL is safe. Lab preparation
must establish those controls. Local same-account/admin modification can defeat
baseline or evidence trust; object identities are not cryptographic provenance.

## Verification performed and release gates

The tests were written before this adapter. The first run failed because the
implementation did not exist. Non-impact tests use newly generated disposable
temporary data only; no replacement, fixture encryption, recovery write or
destructive race exercise has been executed on the current workstation.

The current managed Windows execution token cannot open the
`C:\Users\Admin` ancestor with `CreateFileW` (Windows error 5), even for metadata
access. Other tested ancestors can be opened, so ignoring the denied ancestor
would silently weaken the boundary. The implementation instead fails closed.
Native tests that encounter this exact access-denied prerequisite report
`BLOCKED` using unittest's skip mechanism. These are not passing platform
safety results and they block release of the corresponding filesystem feature.

Latest component check: `python -m unittest discover -s tests -p test_storage.py
-v` discovered 14 tests: **4 passed, 10 environment-blocked/skipped**. A syntax
compile check of `ransomlab/storage.py` also passed. This does not establish
that native file creation, replacement, pinning or leases work on a target VM.

Required remaining evidence on an approved disposable Windows 11 VM includes
all native creation/read/lease checks, reparse and ancestor replacement tests,
hard-link introduction races, checked-handle replacement/partial-write faults,
SQLite main/sidecar substitution, same-process and cross-process leases, and
full baseline recovery verification. Linux support needs equivalent target
filesystem testing and review of the declared same-user race limitation.
