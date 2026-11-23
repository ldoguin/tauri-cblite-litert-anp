#!/bin/bash
# Install the official ANP Python SDK into ~/anp-interop/libs, with no apt, venv or ensurepip: pip's own wheel runs as a zip.
# Pinned to the version this project was checked against.
set -e
SDK_VERSION="${SDK_VERSION:-1.0.7}"
D=${ANP_INTEROP_HOME:-$HOME/anp-interop}
rm -rf "$D" && mkdir -p "$D/dl" && cd "$D"
URL=$(python3 -I - <<'PY'
import json, urllib.request
j = json.load(urllib.request.urlopen("https://pypi.org/pypi/pip/json", timeout=30))
print([x for x in j["urls"] if x["filename"].endswith(".whl")][0]["url"])
PY
)
curl -sSfL "$URL" -o dl/pip.whl
python3 dl/pip.whl/pip install --quiet --disable-pip-version-check --target "$D/libs" "anp==$SDK_VERSION"
python3 -I -c "import sys; sys.path.insert(0,'$D/libs'); import anp; print('anp installed at', anp.__file__)"