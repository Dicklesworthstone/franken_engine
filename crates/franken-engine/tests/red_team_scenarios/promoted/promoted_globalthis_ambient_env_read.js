#! /usr/bin/env node
"use strict";
// franken-engine:corpus-promotion:v1 name=promoted_globalthis_ambient_env_read repro_id=mr-281eed0cda039aa7
// Promoted from a successful red-team attack: minimized via
// hierarchical_delta_debug and gated by acquisition_experiment_oracle.
// Regression contract: FrankenEngine must fail closed on this program.
const ambient = globalThis.process;
