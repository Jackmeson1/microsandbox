# Saved runtime defaults

This module implements the runtime-default selection stage of PR3's saved-config resolver. It is not called by snapshot capture, sandbox launch or exec yet. The required saved-config extension remains unsupported until the complete consumer and capture paths are integrated in this PR.

`select_runtime_defaults` accepts validated portable runtime metadata, the existing sparse `SandboxSpecPatch`, structural clear selectors and trusted operation facts. It returns the surviving lower-priority saved overlay, unresolved binding consumers, unknown fields and full-resume script identity obligations. The explicit destination patch stays separate, so this stage cannot copy destination credentials or scripts into portable metadata.

Native collection replacement and merge are distinct. An empty merge preserves saved environment entries; an empty replacement removes the optional saved map. Per-key merge removes only the overridden source entries. The generated `replaces_*` patch accessors expose existing replacement intent without changing patch application or serialization. Config-file decoding retains its released merge behavior.

Clears are validated against the original source before any are applied. Repeating a key clear or combining it with a whole-map clear is order-independent. Missing keys and unavailable map contents produce a redacted error; clearing the whole optional field can discard unknown contents. Map keys containing dots remain literal keys.

Fresh disk boot discards optional defaults. Fresh full resume still retains captured init, hostname, script backing and clock evidence. This stage rejects a new initial command or init/hostname overrides during full resume. Script replacements retain the original evidence and return identity proof obligations, including empty whole-map replacement; they are never approved merely because this selector succeeds. No script is executed here.

The entrypoint/CMD policy remains a maintainer decision: existing image merging retains CMD when only entrypoint changes, whereas the plan also mentions clearing incompatible saved CMD. `SavedCmdPolicy` is an internal explicit review parameter with no default and no CLI flag. Neither policy is wired into launch. If reset is selected, `reset_inherited_cmd` must also block older image CMD fallback when the final layers are assembled.

Integration must still resolve bindings at their actual consumer's activation time, enforce mandatory destination/security policy, preserve captured resource compatibility, validate full-state script backing, and apply the original destination patch in its existing order. Saved generated hostnames require destination identity regeneration. Optional-field clears must be reconciled with image and legacy defaults during final assembly. These responsibilities are not fulfilled by returning a surviving overlay, and import/inspect success does not authorize execution.
