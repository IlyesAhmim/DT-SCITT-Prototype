"""Evidence overlay used by the event-level study.

This subpackage implements the proof objects, checkpoint semantics, shared log,
and verification procedure as the article defines them, with real Ed25519
signatures, a local time-stamping service, and a Merkle log whose tree heads
are co-signed by consortium members running in separate processes. The
original mock pipeline in ``core``, ``storage``, and ``verification`` is kept
unchanged next to it.
"""
