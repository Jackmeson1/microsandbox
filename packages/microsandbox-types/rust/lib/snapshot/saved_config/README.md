# Saved configuration implementation notes

This is an internal PR3 implementation stage, not an enabled capture or restore feature. The approved contract is `planning/microsandbox/todo/lifecycle-saved-config-design.md`. The complete PR must implement that contract's other policy families, capture provenance and exclusions, mode-specific resolution, destination binding enforcement, CLI/SDK controls and live qualification before advertising `microsandbox.sandbox-config` in `SUPPORTED_REQUIRES`. No existing writer, descriptor reader, launch protocol or persisted sandbox configuration is changed by this module.

## Runtime representation

The runtime section has a closed field inventory: workdir, shell, entrypoint, cmd, env, scripts, init, hostname, user and guest clock. Invocation, logging, metrics configuration, host paths, credentials and arbitrary operational fields are not runtime fallback fields. Resources, labels, security, lifetime, networking, external bindings, provenance and pending configuration belong to separate sections of the complete schema; they are not implemented here yet.

Each field distinguishes absence from `{ "state": "default" }`, `{ "state": "unknown", "reason": "not_recorded" }`, and `{ "state": "value", "value": ..., "origin": "configured" }`. Unknown reasons are closed (`not_recorded`, `not_observed`, `converging`), and origins are closed (`configured`, `image`, `platform`, `observed`). Origins describe evidence; they are never authorization or archive-selected reuse policy. Present null is invalid. Explicit empty argv/maps and false/zero in applicable typed fields remain values.

Command/init text has either a literal value or a logical binding ID. Ordinary declared literal values are preserved exactly, including empty text; typed secret capture and exclusion are separate prerequisites and must not be inferred from variable names. A binding cannot contain a resolved value. Script bodies retain exact normalized UTF-8 content, permission bits and a SHA-256 digest, or a logical binding with neither content nor hash. Scripts are data to reconstruct, never restore hooks. Full-state script handle/backing compatibility remains an additional activation gate; matching this digest alone does not establish it.

Init distinguishes a known builtin choice from unknown history. A handoff records original auto/path selection, the observed absolute guest executable, arguments and init environment. Saved auto does not rerun discovery. Generated versus explicit hostname is retained as a separate tagged choice. Relative guest command workdirs and shell names preserve existing command lookup semantics; these are not host paths.

`binding_requirements()` derives potential consumers from actual typed references. Init uses imply `BootInit`; entrypoint/CMD/env uses imply `NewCommand`; script references imply `ScriptBacking`. Shared IDs retain every consumer. This is not a resolver or a readiness decision: resolution must first apply mode, clears and overrides, validate the inventory, combine gateway/captured-execution requirements and enforce the resulting immediate/deferred demands. An artifact-supplied consumer claim cannot downgrade an actual init use to a future command.

## Draft bounds and diagnostics

These internal limits are explicit, tested and subject to the complete schema's milestone-1 review before exposure. Encoded saved config is bounded to 512 KiB within the descriptor's existing 1 MiB limit; maps/argument lists to 256 entries; nesting to 24 levels; each inline script to 64 KiB and all inline scripts to 256 KiB. Logical binding IDs use at most 128 ASCII alphanumeric, dot, underscore or hyphen bytes. Names are bounded to 256 UTF-8 bytes. Text arguments/env values are bounded to 64 KiB and exclude NUL; guest command settings/user/init paths are bounded to 4096 bytes. Script names must be a single component; destination-specific filename restrictions still need enforcement before host materialization. Permission bits exclude setuid, setgid, sticky and object-type bits.

Decode rejects duplicate keys before typed conversion and unknown fields at every operational record, including empty variants. Serde internally tagged unit variants do not reject additional fields, so the empty default/builtin variants deliberately use strict empty struct variants. Existing `SnapshotManifestError::ManifestParse` carries `SCFG_JSON`, `SCFG_SCHEMA`, `SCFG_LIMIT`, `SCFG_VALUE`, `SCFG_BINDING` or `SCFG_INTEGRITY` plus a fixed field path and safe explanation. Rejected values and unknown keys are not echoed. Debug output for saved values hides literal content and binding IDs. The complete descriptor boundary must preserve this redaction behavior too.

## Remaining integration gates

- Complete the current-head field/API inventory and the rest of the typed schema, including binding inventories and cross-projection checks.
- Implement saved/fresh, field/key clears, explicit input precedence and destination constraints in the shared resolver.
- Capture coherent active configuration, separate pending intent, and trustworthy resolved init/script/resource evidence. The current catalog has `active_config`, but terminal maintenance clears it; desired `config` is not evidence of the last active state.
- Preserve exclusions and secret provenance through all fields, pending data and errors; implement every deferred exec consumer before enabling deferred bindings.
- Connect installed/archive capture, import/verify, disk/full activation, every CLI/SDK path and explicit old-reader refusal.
- Qualify real guests, first traffic, script backing/handles, source deletion, config races, historical artifacts and cancellation on the authorized Mac/Linux hosts.
