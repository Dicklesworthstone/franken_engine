# Fleet Partition Profiles Test Fixtures

## Purpose
Test fixtures for fleet partition fault injection testing. Referenced by:
- B.4 partition fault profiles + chaos vectors for fleet SLO

## Contents
- `profile_permanent_split.json`: Permanent network partition scenario
- `profile_split_brain.json`: Even split that breaks quorum
- `profile_minority_partition.json`: Minority partition scenario
- `profile_healing_network.json`: Network healing after partition
- `chaos_vectors.json`: Chaos engineering test vectors

## Generation
These profiles define network partition scenarios for testing fleet convergence behavior.
Based on the fleet_partition_fault_profiles_v1.json schema used by convergence SLO gates.

## Schema Reference
Profiles follow the franken-engine.fleet-partition-fault-profiles.v1 schema:
- partition_mode: normal, degraded, healing
- message_success_rate: 0-100 percentage
- local_partition_size: number of nodes in partition
- total_fleet_size: total fleet size
- expected_convergence: boolean indicating if convergence should be possible

## Validation
Content hashes are recorded in `fixture_manifest.json`.
Profiles are validated against the convergence gate configuration.