---
name: Initiative / large change (design record)
about: Optional planning record for a large, multi-PR initiative. Not needed for routine issues or single PRs.
title: "[Initiative] <name>"
labels: ["initiative"]
---

<!-- Optional. Use this only for a large, multi-PR initiative, to agree the design up front.
     Routine changes do not need it: open a normal issue or go straight to a PR.
     This is a planning artifact, not a required change record. -->

## Scope & goals
<!-- What this initiative delivers, and explicitly what it does NOT -->

## Affected systems
<!-- Services / repos touched, blast radius, cross-team dependencies -->

## Data & classification
<!-- Data touched and its ITIS-004 classification; encryption / key impact (ITIS-034) -->

## Security review
<!-- Threat model / abuse cases, new attack surface. Does this need a design-stage security review? (ITIS-033) -->

## Test strategy
<!-- How we will prove it works: unit / integration / e2e coverage. Testability risks (what is hard to test, and the plan) -->

## Rollout & rollback
<!-- Phasing, feature flags, data migration, revert path -->

## New dependencies
<!-- New libraries / services / subprocessors (SCA + subprocessor impact) -->

## Approvers / stakeholders
<!-- Design sign-off before the first PR -->

## Tracking
<!-- Linked PRs; exit criteria / definition of done -->
