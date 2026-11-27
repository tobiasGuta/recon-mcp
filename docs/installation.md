# Installation

Use the sealed stable release for the qualified Fedora environment. Use an editable checkout for development, with its own synthetic policy and output. The [compatibility matrix](compatibility.md) records the test evidence for other environments.

## Qualified stable Fedora installation

Use Fedora Linux 45 x86_64, the GIL-enabled Fedora CPython 3.15.2 at `/usr/bin/python3.15`, Bash, curl, GNU coreutils, tar, and util-linux `unshare`. Use a physical, operator-owned path on a supported local filesystem. The release procedure requires a user and network namespace. If the platform refuses the namespace, use a qualified Fedora environment that permits it. Run these blocks in order in the same Bash shell.

### Acquire and verify the release

Use the three named attachments from the [v0.2.0 release](https://github.com/tobiasGuta/recon-mcp/releases/tag/v0.2.0). The source attachment is the published `recon-mcp-0.2.0.tar.gz`. GitHub also generates automatic source archives.

Check the release and expected digests through a trusted channel before using the archives. The checks below establish integrity relative to the expected digests. Publisher authenticity depends on how you obtained and trusted those digests.

```bash
set -eu
umask 077
bundle=$(mktemp -d -t recon-release.XXXXXXXX)
release_url=https://github.com/tobiasGuta/recon-mcp/releases/download/v0.2.0
for asset in SHA256SUMS recon-mcp-0.2.0.tar.gz \
  recon-mcp-0.2.0-fedora45-cpython315-x86_64-wheelhouse.tar.gz; do
  curl --fail --location --silent --show-error "$release_url/$asset" --output "$bundle/$asset"
done

(
  cd -- "$bundle"
  printf '%s  %s\n' \
    3d031ba9685a942b0b78dcd42fe6bf55405b558db5edd6ffd0fb882ddc929c48 SHA256SUMS \
    | sha256sum --check --strict -
  sha256sum --check --strict SHA256SUMS
  tar -xzf recon-mcp-0.2.0.tar.gz
  tar -xzf recon-mcp-0.2.0-fedora45-cpython315-x86_64-wheelhouse.tar.gz
)
candidate="$bundle/recon-mcp-0.2.0"
wheelhouse="$bundle/fedora45-cpython315"
```

The published SHA-256 values for the source and wheelhouse are `db74cca4323ebe8f9c851caade75dfc3d56334f0892ee162e7b53701b5354634` and `876f9ed65241cf7339fef24b7e42cf61fc1e4d397250062d2ec5566732d188e0`, respectively.

### Build, seal, and activate

This block is for a fresh deployment. The stable root must be absent before installation. See [Deployment](deployment.md) for an existing installation. The network namespace encloses venv creation, wheel installation, and dependency checks. After activation, the launcher starts a normal local server process and Recon MCP applies its own runtime scope and transport controls.

```bash
set -eu
umask 077
root="${RECON_DEPLOY_ROOT:-$HOME/.local/share/recon-mcp}"
base=/usr/bin/python3.15
version=0.2.0
lock="$candidate/release/fedora45-cpython315-runtime.requirements.txt"

(cd -- "$wheelhouse" && sha256sum --check --strict SHA256SUMS)
cmp -- "$lock" "$wheelhouse/fedora45-cpython315-runtime.requirements.txt"
cmp -- "$candidate/release/fedora45-cpython315-qualification.requirements.txt" \
  "$wheelhouse/fedora45-cpython315-qualification.requirements.txt"
cmp -- "$candidate/release/fedora45-cpython315-wheel-provenance.json" \
  "$wheelhouse/fedora45-cpython315-wheel-provenance.json"

# Use these initial directory and launcher commands only for the first install.
mkdir -p -- "$(dirname -- "$root")"
mkdir -- "$root"
mkdir -- "$root/releases" "$root/runtime"
mkdir -- "$root/runtime/config" "$root/runtime/output"
install -m 0700 -- "$candidate/scripts/stable_deployment.py" "$root/stable_deployment.py"

release="$root/releases/$version"
mkdir -- "$release"
mkdir -- "$release/source"
cp -R -- "$candidate/recon" "$candidate/server.py" "$release/source/"
"$base" -I -S -B -c 'import platform, sys, sysconfig; assert sys.platform == "linux" and platform.machine() == "x86_64" and sys.version_info[:3] == (3, 15, 2) and sys._is_gil_enabled() and not sysconfig.get_config_var("Py_GIL_DISABLED"); print(sys.version)'
unshare --user --map-current-user --net -- "$base" -I -B -m venv --copies "$release/.venv"
py="$release/.venv/bin/python"
unshare --user --map-current-user --net -- env PIP_CONFIG_FILE=/dev/null \
  "$py" -I -B -m pip --isolated --disable-pip-version-check install \
  --no-index --no-deps --only-binary=:all: --require-hashes --no-compile \
  --find-links "$wheelhouse" -r "$lock"
unshare --user --map-current-user --net -- env PIP_CONFIG_FILE=/dev/null \
  "$py" -I -B -m pip --isolated --disable-pip-version-check check
"$py" -I -B - "$candidate/release/fedora45-cpython315-runtime.txt" <<'PY'
import importlib.metadata as metadata
import re
import sys
from pathlib import Path

def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()

expected = {"pip": "26.3"}
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.strip() and not line.startswith("#"):
        name, version = line.split("==")
        expected[normalized(name)] = version
actual = {}
for dist in metadata.distributions():
    name = normalized(dist.metadata["Name"])
    assert name not in actual and dist.read_text("direct_url.json") is None, name
    actual[name] = dist.version
assert actual == expected, (expected.items() - actual.items(), actual.items() - expected.items())
PY

(cd -- "$release/source" && "$py" -E -s -B -c \
  'import recon, server; assert recon.__version__ == "0.2.0"; assert len(server.AVAILABLE_TOOLS) == 67')
"$py" -E -s -B "$release/source/server.py" </dev/null
guard="$root/stable_deployment.py"
digest=$("$base" -I -S -B "$guard" seal "$root" "$version")
printf '%s %s\n' "$version" "$digest"
# Record the printed digest in your deployment record.
"$base" -I -S -B "$guard" activate "$root" "$version" "$digest"
"$base" -I -S -B "$guard" verify "$root"
"$base" -I -S -B "$guard" serve "$root" </dev/null
```

The install checks 33 pinned runtime distributions, including pip. The same wheelhouse includes ten additional wheels for the separate qualification environment. The version and SHA-256 printed by `seal` identify the local manifest. Keep that digest in a separate deployment record. `verify` reports the active version and manifest SHA-256. Guarded startup with stdin at EOF should exit successfully. For a live local connection check, [register a client](client-setup.md) and call `health`.

The root contains `stable_deployment.py`, `releases/0.2.0/{source,.venv,manifest.json}`, and `runtime/{server.py,recon,config,output}`. The launcher writes `deployment-metadata.json` and uses `.deployment.lock`. See [stable layout and locks](deployment.md#layout-and-locks). You can set `RECON_DEPLOY_ROOT` to an unused physical absolute path to install a disposable instance for diagnostics.

## Development installation

Use Python 3.11 or newer within the package's declared dependency constraints. Fedora 45 and CPython 3.15.2 are the qualified combination. Install the OpenSSL CLI to run the real loopback TLS tests. Use a private local checkout and review the selected Git revision before installing.

```bash
umask 077
git clone https://github.com/tobiasGuta/recon-mcp.git
cd recon-mcp
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q release/tests/test_stable_deployment.py
```

The editable install uses files from the checkout immediately. The package resolver can contact its configured package index. For exact offline regression reproduction, use the [qualification wheelhouse procedure](v0.2.0-release-preparation.md#clean-offline-regression-environment) with the separate qualification lock.

Configure the client to run the checkout's `.venv/bin/python` with the checkout's absolute `server.py` path. A manual launch from the checkout runs the same STDIO process.

```bash
.venv/bin/python -B server.py
```

An idle process is waiting for protocol input. Press Ctrl+C to return to the shell. Use a separate name such as `recon-dev` and keep synthetic `config/scope.json`, policy sources, and `output/` in the checkout. The server derives these paths from its loaded source tree. Changing the client's working directory alone does not relocate them.

## Other platforms

Package declarations permit Python `>=3.11`, MCP SDK 1.x, HTTPX 0.29.x, and HTTPCore 1.0.x beginning at 1.0.9. Different platforms and resolved versions carry different compatibility evidence. Windows is unverified, and campaign storage needs the Linux locking backend and a supported local mount. macOS, ARM, and other Fedora or Python builds are outside the qualified stable package. See the [compatibility matrix](compatibility.md).
