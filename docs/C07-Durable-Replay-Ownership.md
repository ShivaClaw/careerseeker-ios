# C07 — durable replay ownership across app processes

**Status:** binding design constraint for future app-layer work. The Linux SDK now proves
replay-boundary restoration; app/extension storage and process coordination remain
UNPROVEN until an Apple hardware/Xcode lane exists.

## Decision

For each pairing stream, exactly one durable owner may commit accepted replica data and
its replay checkpoint. A future iPhone app and Notification Service Extension must not
both advance that state.

The durable owner must apply these two effects in one transaction:

1. commit the accepted payload's replica changes; and
2. store the receiver's resulting `ReplayBoundary`.

A crash before the transaction commits leaves both unchanged, so the envelope can be
retried. A crash after commit leaves both advanced, so the same envelope is rejected as a
replay. Committing either half alone is invalid: replica-only commit permits duplicate
application, while checkpoint-only commit loses an update permanently.

The eventual shared App Group store must provide cross-process exclusion around this
transaction. In-process serialization alone is insufficient because the app and extension
can run concurrently.

## Notification presentation path

The Notification Service Extension may use a **noncommitting decrypt path** to render a
notification from a snapshot of pairing keys and the last durable replay boundary. That
path must not mutate the replica, persist a new checkpoint, or claim ownership of the
stream. It is a preview for presentation only; the durable owner later performs normal
acceptance and the atomic commit.

If the extension cannot obtain a consistent snapshot, it must fall back to generic
notification content rather than race the durable owner or reset a boundary. No app or
extension target is created by this note.

## Required future evidence

- a storage transaction test proving replica and checkpoint commit or roll back together;
- a two-process race test proving only one durable owner can commit;
- a notification-extension test proving presentation does not advance persisted replay
  state; and
- Apple hardware evidence for the actual App Group/extension integration.
