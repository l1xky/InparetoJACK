#!/data/data/com.termux/files/usr/bin/bash

set -euo pipefail
export PATH="/data/data/com.termux/files/usr/bin:${PATH:-}"
export DEBIAN_FRONTEND=noninteractive
export PIP_BREAK_SYSTEM_PACKAGES=1
export PIP_DEFAULT_TIMEOUT=90

REPO="https://github.com/l1xky/InparetoA.git"
DIR="${INPARETO_DIR:-$HOME/inpareto}"
# Pure-Python only — do NOT add TUR index here (slow resolver + wrong wheels)
PIP=(python3 -m pip install --break-system-packages --no-cache-dir -q)
TUR_INDEX="https://termux-user-repository.github.io/pypi/"
# Py3.13+ Termux: pip accepts android_* tags, not linux_aarch64 (see termux-packages #25150)
TUR_PY313_CORE_VER="2.41.5"
LOG="/data/data/com.termux/files/usr/tmp/inpareto-setup-$$.log"
TOTAL_STEPS=5
CURRENT_STEP=0

# ── UI (colors + spinner) ───────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R=$'\033[0m' B=$'\033[1m' D=$'\033[2m'
  C=$'\033[36m' G=$'\033[32m' Y=$'\033[33m' M=$'\033[35m' RED=$'\033[31m'
else
  R=$'' B=$'' D=$'' C=$'' G=$'' Y=$'' M=$'' RED=$''
fi

_SPIN_PID=""
_SPIN_MSG=""

_spin_stop() {
  [[ -n "$_SPIN_PID" ]] && kill "$_SPIN_PID" 2>/dev/null && wait "$_SPIN_PID" 2>/dev/null || true
  _SPIN_PID=""
  printf "\r\033[K"
}

_spin_start() {
  _SPIN_MSG="$1"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  (
    local i=0
    while true; do
      printf "\r  ${C}%s${R}  %s" "${frames[$((i % ${#frames[@]}))]}" "$_SPIN_MSG"
      sleep 0.12
      i=$((i + 1))
    done
  ) &
  _SPIN_PID=$!
}

ui_banner() {
  clear 2>/dev/null || true
  echo -e "${C}${B}"
  cat <<'ART'
    ██╗███╗   ██╗██████╗  █████╗ ██████╗ ███████╗████████╗ ██████╗
    ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗
    ██║██╔██╗ ██║██████╔╝███████║██████╔╝█████╗     ██║   ██║   ██║
    ██║██║╚██╗██║██╔═══╝ ██╔══██║██╔══██╗██╔══╝     ██║   ██║   ██║
    ██║██║ ╚████║██║     ██║  ██║██║  ██║███████╗   ██║   ╚██████╔╝
    ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝
ART
  echo -e "${R}${D}    Termux installer · 0.119+ · auto-confirm · @Developyer${R}"
  echo -e "${D}    Log: $LOG${R}"
  echo ""
}

ui_line() { echo -e "${D}────────────────────────────────────────────────${R}"; }

ui_step() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  ui_line
  echo -e "${M}${B}  STEP ${CURRENT_STEP}/${TOTAL_STEPS}${R}  ${B}$*${R}"
  echo ""
}

ui_ok()   { echo -e "  ${G}✔${R}  $*"; }
ui_warn() { echo -e "  ${Y}⚠${R}  $*"; }
ui_info() { echo -e "  ${D}›${R}  $*"; }

fail() {
  _spin_stop
  echo ""
  echo -e "${RED}${B}  ✖ FAILED${R}  $*"
  echo -e "${D}  Log saved: $LOG${R}"
  echo ""
  exit 1
}

run_logged() {
  local title="$1"
  shift
  _spin_start "$title"
  : >"$LOG"
  if "$@" >>"$LOG" 2>&1; then
    _spin_stop
    ui_ok "$title"
    return 0
  fi
  _spin_stop
  echo -e "  ${RED}✖${R}  $title"
  tail -n 25 "$LOG" | sed 's/^/      /'
  fail "$title (see log tail above)"
}

# Auto-answer Y/n on every pkg prompt (Termux keeps asking otherwise)
pkg_auto() {
  local sub="$1"
  shift
  local title="pkg $sub $*"
  _spin_start "$title · auto Y"
  : >>"$LOG"
  echo ">>> pkg $sub $*" >>"$LOG"
  local ec=0
  set +o pipefail
  if command -v yes >/dev/null 2>&1; then
    yes | pkg "$sub" -y "$@" >>"$LOG" 2>&1 || ec=$?
  else
    pkg "$sub" -y "$@" >>"$LOG" 2>&1 || ec=$?
  fi
  set -o pipefail
  # yes gets SIGPIPE (141) when pkg exits — that is OK
  if [[ $ec -ne 0 && $ec -ne 141 ]]; then
    ui_warn "retry pkg $sub (plain -y)…"
    pkg "$sub" -y "$@" >>"$LOG" 2>&1 || ec=$?
  fi
  [[ $ec -eq 141 ]] && ec=0
  _spin_stop
  if [[ $ec -eq 0 ]]; then
    ui_ok "$title"
    return 0
  fi
  tail -n 20 "$LOG" | sed 's/^/      /'
  fail "pkg $sub failed"
}

# ── Guards ────────────────────────────────────────────────────────────────────
# V9+ writes start-api.sh — do NOT grep for that string in $0 (false positive).
if grep -q 'INPARETO_SETUP_V9' "$0" 2>/dev/null; then
  : # current Termux installer
elif grep -qE '^(step|ok|die)\(\)|install-termux\.sh' "$0" 2>/dev/null; then
  echo "Delete old installer. Run:"
  echo "  curl -fsSL https://raw.githubusercontent.com/l1xky/InparetoA/main/setup.sh -o setup.sh && bash setup.sh"
  exit 1
fi

[[ -d /data/data/com.termux ]] || fail "Open the Termux app on Android."
[[ -n "${HOME:-}" ]] || export HOME="/data/data/com.termux/files/home"
DIR="${DIR/#\~/$HOME}"

# Map CPU → TUR android wheel platform tag (Py3.13+) or Eutalix linux tag (older Python)
pydantic_plat_tags() {
  local arch="$1" py_minor="$2"
  if [[ "$py_minor" -ge 13 ]]; then
    case "$arch" in
      aarch64)     echo "android_24_arm64_v8a" ;;
      armv7l|armv8l) echo "android_24_armeabi_v7a" ;;
      x86_64)      echo "android_24_x86_64" ;;
      i686|i386)   echo "android_24_x86" ;;
      *) return 1 ;;
    esac
  else
    case "$arch" in
      aarch64)     echo "linux_aarch64" ;;
      armv7l|armv8l) echo "linux_armv7l" ;;
      x86_64)      echo "linux_x86_64" ;;
      i686|i386)   echo "linux_i686" ;;
      *) return 1 ;;
    esac
  fi
}

unset_pip_constraint() {
  unset PIP_CONSTRAINT 2>/dev/null || true
}

# pydantic_core imports typing_extensions — must exist before any core import check.
bootstrap_typing_extensions() {
  _spin_start "typing-extensions (bootstrap)"
  python3 -m pip install 'typing-extensions>=4.14.1' \
    --break-system-packages --no-cache-dir -q >>"$LOG" 2>&1 \
    || { _spin_stop; fail "typing-extensions bootstrap"; }
  _spin_stop
  ui_ok "typing-extensions ready"
}

purge_pydantic_stack() {
  unset_pip_constraint
  echo ">>> pip uninstall pydantic pydantic-core (clean slate)" >>"$LOG"
  python3 -m pip uninstall -y pydantic pydantic-core >>"$LOG" 2>&1 || true
}

pydantic_core_ready() {
  python3 -c '
import typing_extensions  # noqa: F401
import pydantic_core
v = tuple(int(x) for x in pydantic_core.__version__.split(".")[:2])
raise SystemExit(0 if v >= (2, 41) else 1)
' >/dev/null 2>&1
}

# Unzip wheel into site-packages (bypasses pip platform-tag rejection on Termux Py3.13).
force_install_wheel() {
  local whl="$1"
  python3 - "$whl" >>"$LOG" 2>&1 <<'PY'
import glob, os, shutil, sys, zipfile, sysconfig
whl = os.path.abspath(sys.argv[1])
dest = sysconfig.get_paths()["purelib"]
for old in glob.glob(os.path.join(dest, "pydantic_core*")):
    if os.path.isdir(old):
        shutil.rmtree(old, ignore_errors=True)
with zipfile.ZipFile(whl) as z:
    for info in z.infolist():
        if info.is_dir():
            continue
        target = os.path.join(dest, info.filename)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with z.open(info) as src, open(target, "wb") as out:
            out.write(src.read())
print("force_install_wheel OK:", whl)
PY
}

pydantic_core_wheel_meta() {
  # Sets: ver name url (for current arch/python)
  local arch="$1" py_minor="$2" py_abi="$3" plat="$4"
  if [[ "$py_minor" -ge 13 ]]; then
    ver="$TUR_PY313_CORE_VER"
    name="pydantic_core-${ver}-${py_abi}-${py_abi}-${plat}.whl"
    url="https://github.com/tur-pypi-dists/python3.13-pydantic_core/releases/download/v${ver}/${name}"
  else
    ver="2.46.3"
    name="pydantic_core-${ver}-${py_abi}-${py_abi}-${plat}.whl"
    url="https://github.com/Eutalix/android-pydantic-core/releases/download/v${ver}/${name}"
  fi
}

install_pydantic_core() {
  local arch plat py_abi py_minor url name tmp save_dir ver whl_path

  save_dir="$(pwd)"
  arch="$(uname -m)"
  py_minor="$(python3 -c 'import sys; print(sys.version_info.minor)')"
  py_abi="$(python3 -c 'import sys; print(f"cp{sys.version_info.major}{sys.version_info.minor}")')"
  plat="$(pydantic_plat_tags "$arch" "$py_minor")" \
    || fail "unsupported CPU for pydantic-core: $arch"

  pydantic_core_wheel_meta "$arch" "$py_minor" "$py_abi" "$plat"
  ui_info "Target wheel: $name"

  if pydantic_core_ready; then
    ui_ok "pydantic-core already OK ($(python3 -c 'import pydantic_core; print(pydantic_core.__version__)'))"
    return 0
  fi

  purge_pydantic_stack
  tmp="$(mktemp -d)"
  cd "$tmp" || fail "temp dir"
  whl_path="$tmp/$name"

  _spin_start "Downloading pydantic-core"
  if ! curl -fL -H "User-Agent: InparetoSetup/8" -o "$name" "$url" >>"$LOG" 2>&1; then
    _spin_stop
    cd "$save_dir" || true
    rm -rf "$tmp"
    fail "pydantic-core download failed — check network ($url)"
  fi
  _spin_stop
  ui_ok "Downloaded $name"

  # 1) Manual extract FIRST — Termux Py3.13 often rejects pip wheel tags; extract always works.
  _spin_start "Installing pydantic-core (extract)"
  purge_pydantic_stack
  if force_install_wheel "$whl_path" && pydantic_core_ready; then
    _spin_stop
    rm -rf "$tmp"
    cd "$save_dir" || true
    ui_ok "pydantic-core $(python3 -c 'import pydantic_core; print(pydantic_core.__version__)') (extract)"
    return 0
  fi
  _spin_stop
  ui_warn "extract install incomplete — trying pip"

  # 2) pip install local wheel (sometimes works after purge)
  _spin_start "Installing pydantic-core (pip wheel)"
  purge_pydantic_stack
  if python3 -m pip install "$whl_path" \
      --break-system-packages --no-deps --force-reinstall --no-cache-dir -q >>"$LOG" 2>&1 \
      && pydantic_core_ready; then
    _spin_stop
    rm -rf "$tmp"
    cd "$save_dir" || true
    ui_ok "pydantic-core $(python3 -c 'import pydantic_core; print(pydantic_core.__version__)') (pip wheel)"
    return 0
  fi
  _spin_stop

  # 3) TUR index — exact pin + --no-deps (no 2.35.2 vs 2.41.5 conflict)
  _spin_start "pydantic-core==${ver} (TUR pip)"
  purge_pydantic_stack
  if python3 -m pip install "pydantic-core==${ver}" \
      --index-url "$TUR_INDEX" \
      --no-deps --break-system-packages --no-cache-dir -q >>"$LOG" 2>&1 \
      && pydantic_core_ready; then
    _spin_stop
    rm -rf "$tmp"
    cd "$save_dir" || true
    ui_ok "pydantic-core $(python3 -c 'import pydantic_core; print(pydantic_core.__version__)') (TUR)"
    return 0
  fi
  _spin_stop

  cd "$save_dir" || true
  rm -rf "$tmp"
  tail -n 30 "$LOG" | sed 's/^/      /'
  fail "pydantic-core install failed (see log tail)"
}

# Pin so later pip steps never replace TUR android pydantic-core with PyPI manylinux.
write_pip_constraint() {
  local ver
  ver="$(python3 -c 'import pydantic_core; print(pydantic_core.__version__)')"
  export PIP_CONSTRAINT="${TMPDIR:-/tmp}/inpareto-pip-constraint-$$.txt"
  printf 'pydantic-core==%s\n' "$ver" >"$PIP_CONSTRAINT"
  ui_info "pip constraint: pydantic-core==$ver"
}

verify_python_stack() {
  python3 >>"$LOG" 2>&1 <<'PY'
import sys

def parse_ver(s):
    parts = []
    for p in s.split("."):
        n = ""
        for c in p:
            if c.isdigit():
                n += c
            else:
                break
        parts.append(int(n) if n else 0)
    return tuple(parts[:3])

# Required for endpoint.py + joint.py core
import typing_extensions
import pydantic_core
import typing_inspection
import pydantic
import starlette
import fastapi
import uvicorn
import requests
import urllib3

joint_extras = "ok"
try:
    from cryptography.fernet import Fernet  # noqa: F401
    from PIL import Image  # noqa: F401
except ImportError:
    joint_extras = "missing (pkg install python-cryptography python-pillow)"

pc = parse_ver(pydantic_core.__version__)
pd = parse_ver(pydantic.__version__)
if pd[0] < 2 or (pd[0] == 2 and pd[1] < 12):
    raise SystemExit(
        f"pydantic {pydantic.__version__} is too old for pydantic-core {pydantic_core.__version__}; "
        "need pydantic>=2.12 (re-run setup.sh)"
    )
if pc[0] < 2 or (pc[0] == 2 and pc[1] < 41):
    raise SystemExit(
        f"pydantic-core {pydantic_core.__version__} is too old; need >=2.41 from TUR"
    )

print(
    "stack OK",
    f"pydantic-core={pydantic_core.__version__}",
    f"pydantic={pydantic.__version__}",
    f"fastapi={fastapi.__version__}",
    f"joint_extras={joint_extras}",
    f"python={sys.version.split()[0]}",
)
PY
}

# cryptography/Pillow: NEVER pip-compile on Py3.13 (15+ min). Use Termux .deb only.
ensure_joint_extras() {
  if python3 -c "from cryptography.fernet import Fernet; from PIL import Image" 2>/dev/null; then
    ui_ok "cryptography + Pillow ready"
    return 0
  fi
  ui_warn "installing joint extras via pkg (fast — not pip compile)"
  _spin_start "pkg: python-cryptography · python-pillow"
  set +e
  for _jp in python-cryptography python-pillow; do
    pkg install -y "$_jp" >>"$LOG" 2>&1 || true
  done
  set -e
  _spin_stop
  if python3 -c "from cryptography.fernet import Fernet; from PIL import Image" 2>/dev/null; then
    ui_ok "cryptography + Pillow (pkg)"
    return 0
  fi
  ui_warn "joint extras not installed — endpoint.py still works"
  ui_info "Later run: pkg install -y python-cryptography python-pillow"
  return 0
}

install_curl_cffi_optional() {
  # curl_cffi — Chrome/Android TLS; best mobile option for Posts count on hits.
  if python3 - <<'PY' 2>/dev/null; then
try:
    from curl_cffi import requests as cr
    cr.Session(impersonate="chrome131_android")
except Exception:
    raise SystemExit(1)
PY
    ui_ok "curl_cffi ready (Posts count on hits)"
    return 0
  fi
  _spin_start "pip: curl_cffi (IG profile / posts on hits)"
  if python3 -m pip install "curl_cffi>=0.7.0" --break-system-packages --no-cache-dir -q >>"$LOG" 2>&1 \
      && python3 - <<'PY' >>"$LOG" 2>&1
try:
    from curl_cffi import requests as cr
    cr.Session(impersonate="chrome131_android")
except Exception:
    raise SystemExit(1)
PY
  then
    _spin_stop
    ui_ok "curl_cffi installed (chrome131_android)"
    return 0
  fi
  _spin_stop
  ui_warn "curl_cffi not installed — try: pip install curl_cffi"
  return 0
}

install_tls_client_optional() {
  # tls_client .so links libpthread.so.0 — missing on Android/Bionic (Termux).
  if [[ -d /data/data/com.termux ]] || [[ "$(uname -o 2>/dev/null)" == *Android* ]]; then
    if python3 -m pip show tls_client >>"$LOG" 2>&1; then
      ui_warn "Removing tls_client (Termux/Android — libpthread.so.0 missing)"
      python3 -m pip uninstall -y tls_client >>"$LOG" 2>&1 || true
    fi
    ui_info "tls_client skipped on Termux — use curl_cffi for IG profile"
    return 0
  fi
  if python3 - <<'PY' 2>/dev/null; then
try:
    import tls_client
    s = tls_client.Session(client_identifier="okhttp4_android_13", random_tls_extension_order=True)
    del s
except Exception:
    raise SystemExit(1)
PY
    ui_ok "tls_client ready (better Posts count on hits)"
    return 0
  fi
  _spin_start "pip: tls_client (IG profile / posts on hits)"
  if python3 -m pip install tls_client --break-system-packages --no-cache-dir -q >>"$LOG" 2>&1 \
      && python3 - <<'PY' >>"$LOG" 2>&1
try:
    import tls_client
    s = tls_client.Session(client_identifier="okhttp4_android_13", random_tls_extension_order=True)
    del s
except Exception:
    raise SystemExit(1)
PY
  then
    _spin_stop
    ui_ok "tls_client installed"
    return 0
  fi
  _spin_stop
  python3 -m pip uninstall -y tls_client >>"$LOG" 2>&1 || true
  ui_warn "tls_client not installed — Posts may show N/A when IG rate-limits"
  return 0
}

write_launchers() {
  cat > start-api.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")"
export UVICORN_WORKERS=1
echo "INPARETO API — keep open (port 5001) · Posts count needs this running"
exec python3 endpoint.py
EOF
  cat > start-bot.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")"
echo "INPARETO BOT — start start-api.sh in another window FIRST"
exec python3 joint.py
EOF
  chmod +x start-api.sh start-bot.sh
  ui_ok "start-api.sh + start-bot.sh created"
}

# ── Main ──────────────────────────────────────────────────────────────────────
ui_banner

ui_step "System packages"
command -v pkg >/dev/null 2>&1 || fail "pkg not found — update Termux from F-Droid"
ui_info "Auto-confirm: all pkg prompts get Y (no manual input)"
pkg_auto update
pkg_auto upgrade
pkg_auto install python git curl
command -v python3 >/dev/null 2>&1 || fail "python3 missing"
command -v git >/dev/null 2>&1 || fail "git missing"
ui_info "$(python3 -V 2>&1) · arch $(uname -m)"

ui_step "Download INPARETO"
mkdir -p "$(dirname "$DIR")"
if [[ -d "$DIR/.git" ]]; then
  _spin_start "git pull"
  (cd "$DIR" && git pull --ff-only >>"$LOG" 2>&1) || true
  _spin_stop
  ui_ok "Updated $DIR"
elif [[ -f "$DIR/joint.py" && -f "$DIR/endpoint.py" ]]; then
  ui_ok "Already installed at $DIR"
else
  rm -rf "$DIR"
  _spin_start "git clone"
  git clone --depth 1 "$REPO" "$DIR" >>"$LOG" 2>&1 || { _spin_stop; fail "git clone"; }
  _spin_stop
  ui_ok "Cloned → $DIR"
fi
[[ -f "$DIR/joint.py" && -f "$DIR/endpoint.py" ]] \
  || fail "joint.py / endpoint.py missing on GitHub"

ui_step "Python environment"
cd "$DIR" || fail "cd $DIR"
# Fresh log for pip only (avoids mixing old pkg/llvm errors with Python step)
: >"$LOG"
echo "=== INPARETO Python setup $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date) ===" >>"$LOG"
ui_info "Skipping pip upgrade (Termux blocks it — normal)"
unset_pip_constraint
bootstrap_typing_extensions
install_pydantic_core
write_pip_constraint

_spin_start "pip: typing + requests (pure Python)"
"${PIP[@]}" \
  'typing-extensions>=4.14.1' 'annotated-types>=0.6.0' 'typing-inspection>=0.4.2' \
  'requests>=2.31,<3' 'urllib3>=2.0,<3' 'certifi' 'charset-normalizer' 'idna' \
  'starlette>=0.40.0,<0.47.0' 'h11>=0.8' 'click>=7.0' \
  >>"$LOG" 2>&1 \
  || { _spin_stop; fail "base pip packages"; }
_spin_stop
ui_ok "base libraries"

ensure_joint_extras

install_curl_cffi_optional
install_tls_client_optional

# pydantic 2.12+ matches TUR pydantic-core 2.41.x (2.10/2.11 need older core — do not use)
_spin_start "pip: pydantic (pinned, no PyPI core)"
python3 -m pip install 'pydantic>=2.12.0,<2.13' --no-deps --force-reinstall \
  --break-system-packages -q >>"$LOG" 2>&1 \
  || { _spin_stop; fail "pydantic"; }
_spin_stop
ui_ok "pydantic $(python3 -c 'import pydantic; print(pydantic.__version__)')"

_spin_start "pip: fastapi · uvicorn (no-deps)"
python3 -m pip install 'fastapi>=0.110.0,<0.116.0' 'uvicorn>=0.29.0,<0.33.0' \
  --no-deps --break-system-packages -q >>"$LOG" 2>&1 \
  || { _spin_stop; fail "fastapi/uvicorn"; }
_spin_stop
ui_ok "API stack"

_spin_start "Verifying stack (imports + versions)"
if ! verify_python_stack; then
  _spin_stop
  tail -n 30 "$LOG" | sed 's/^/      /'
  fail "import/version check"
fi
_spin_stop
ui_ok "All imports OK"

write_launchers

ui_step "Ready"
echo ""
echo -e "${G}${B}  ╔══════════════════════════════════════════╗${R}"
echo -e "${G}${B}  ║         INPARETO INSTALL COMPLETE          ║${R}"
echo -e "${G}${B}  ╚══════════════════════════════════════════╝${R}"
echo ""
echo -e "${B}  Window 1 — API (start FIRST — Posts count needs this)${R}"
echo -e "    ${C}cd $DIR && bash start-api.sh${R}"
echo -e "    ${D}or: python3 endpoint.py${R}"
echo ""
echo -e "${B}  Window 2 — Bot${R}"
echo -e "    ${C}cd $DIR && bash start-bot.sh${R}"
echo -e "    ${D}or: python3 joint.py${R}"
echo ""
echo -e "${Y}  Posts show N/A?${R}"
echo -e "${D}  1) endpoint.py running in window 1${R}"
echo -e "${D}  2) git pull — update BOTH joint.py + endpoint.py${R}"
echo -e "${D}  3) Termux: pip install curl_cffi (chrome131_android — setup.sh tries this)${R}"
echo -e "${D}  4) Do NOT pip install tls_client on Termux (libpthread crash)${R}"
echo -e "${D}  5) Test: python3 test_termux_curl_posts.py${R}"
echo -e "${D}  6) IG rate-limits IP — lower hunt threads / try VPN${R}"
echo ""
echo -e "${D}  Telegram: token → channels → hit group admin → /verifyhitgroup${R}"
echo -e "${D}  Full log: $LOG${R}"
echo ""
