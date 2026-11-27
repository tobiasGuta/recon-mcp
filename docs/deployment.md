# Stable deployment operations

Follow [Installation](installation.md#qualified-stable-fedora-installation) for the released v0.2.0 bundle. Operate from physical paths under one private, operator-owned root. Use the guarded launcher for every stable MCP registration.

## Layout and locks

```text
~/.local/share/recon-mcp/
├── stable_deployment.py
├── releases/
│   └── 0.2.0/
│       ├── source/
│       ├── .venv/
│       └── manifest.json
├── runtime/
│   ├── server.py
│   ├── recon/
│   ├── config/
│   └── output/
├── deployment-metadata.json
└── .deployment.lock
```

Each release has a sealed code and venv inventory. Activation copies the selected code into the physical runtime. The launcher verifies version, manifest digest, sealed file inventory, permissions, and active source before serving. `deployment-metadata.json` selects the active release and manifest SHA-256. Keep trusted archive digests and recorded manifest digests in a separate private deployment record. The system interpreter and libraries remain OS dependencies. Verify again after their update.

The server process holds a shared deployment lock for its lifetime. Sealing and activation require the exclusive lock. Campaign operations use a different lock in `runtime/output/`. Keep other writers out of the managed runtime code and preserve the stable configuration and output roots between compatible versions.

## Check a deployment

```bash
root="$HOME/.local/share/recon-mcp"
base=/usr/bin/python3.15
guard="$root/stable_deployment.py"
"$base" -I -S -B "$guard" verify "$root"
```

Expect `Verified recon-mcp` followed by a version and manifest SHA-256. Compare both to the deployment record. Use [offline client checks](client-setup.md#codex-cli) to test MCP initialization and health.

## Upgrade or switch versions

1. Acquire and verify the next reviewed release's archives and dependencies using that version's instructions. Confirm platform, policy, and evidence compatibility. Build its versioned source and venv without replacing any existing release. For v0.2.0 into an existing deployment, run the wheelhouse comparisons and resume at `release="$root/releases/$version"` in [Build, seal, and activate](installation.md#build-seal-and-activate). Review launcher changes separately.
2. Rehearse the candidate with separate synthetic state. Stop all attached MCP server processes and other writers before the production `seal` and `activate` calls. Back up private policy sources and campaign data while writers are stopped.
3. Record the manifest SHA-256 printed by `seal`. Run the activation and verification commands below with the candidate version and recorded digest. Verify active policy and offline scope decisions before reopening clients.

```bash
read -r -p 'Reviewed release version: ' selected_version
read -r -p 'Recorded release manifest SHA-256: ' selected_digest
"$base" -I -S -B "$guard" activate "$root" "$selected_version" "$selected_digest" &&
  "$base" -I -S -B "$guard" verify "$root"
```

When migrating from an editable registration, close the old client sessions and remove or disable the old stable-facing entry. Point clients to the guarded launcher. Keep a separate development name and synthetic state if the old checkout remains in use.

## Rollback and interrupted activation

To roll back, stop all clients and use the same activation commands with the previously sealed, compatible release and its recorded digest. Verify code and policy before reconnecting, and review any change in campaign bindings. Synthetic two-version switching and persistent state were covered in qualification. Rolling back to v0.1.0 or interpreting newer campaign data with older runtime code requires separate compatibility evidence.

An interrupted activation can leave the selected metadata and active code out of agreement. The launcher refuses to serve in that state. Stop clients, confirm that the chosen release and recorded manifest are trusted, and re-run `activate` for that sealed version. Check `verify` and offline health before restoring access. The launcher can preserve replaced code in private `.retired-code-*` directories. Review them before cleanup. Preserve the versioned releases and digests you need for recovery.

## Backup and migration

With all writers stopped, back up the physical `runtime/config/` and `runtime/output/` directories and any policy sources referenced elsewhere. Preserve active and archived trees, audit and integrity metadata, and original evidence bytes. Record hashes, protect backup permissions, and verify a disposable restore before depending on it. Keep the recovered and original trees separate while inspecting them. See [evidence retention](evidence-management.md#sensitive-data-and-retention).

For a reviewed migration, identify one authoritative campaign tree. Check source and destination ownership, private permissions, links, and mount type. Prefer a same-filesystem rename of the verified tree into an empty destination with writers stopped. A cross-filesystem migration requires verified copy and cutover. Confirm there is only one writable campaign tree before resuming. Legacy records can contain historical absolute paths. Preserve their provenance and run the integrity checks on the destination.

Review and activate the migrated policy separately using [offline validation and migration](scope-authorization.md#offline-validation-and-migration). Check its fingerprint and reauthorize affected campaigns locally where appropriate. To retire a deployment, remove client registrations, preserve the required private state and its verified backup, then review old code and artifacts under the applicable retention terms.
