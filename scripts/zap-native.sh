#!/bin/sh
# cosentinel ZAP shim — run a NATIVE OWASP ZAP "quick scan" (spider + active
# scan) from the CLI and write a JSON report.
#
# Why this exists: the ZAP adapter is written against the packaged-scan script
# `zap-full-scan.py`, which only ships inside ZAP's Docker image — and a Docker
# container on Docker Desktop can't reach a Tailscale IP. This shim lets ZAP run
# natively on the host (so the tailnet is reachable) by translating the adapter's
# `zap-full-scan.py`-style flags (-t URL, -J report, -I) into
# `zap.sh -cmd -quickurl … -quickout …`.
#
# Point the adapter at it:
#   export COSENTINEL_ZAP="$PWD/scripts/zap-native.sh"
#
# Overridable: JAVA_HOME (a JDK 17+), ZAP_SH (path to zap.sh).

# --- locate a Java runtime (ZAP needs 17+) --------------------------------
if [ -z "${JAVA_HOME:-}" ]; then
  for j in /opt/homebrew/opt/openjdk@21 /opt/homebrew/opt/openjdk \
           /usr/local/opt/openjdk@21 /usr/local/opt/openjdk; do
    if [ -x "$j/bin/java" ]; then JAVA_HOME="$j"; break; fi
  done
fi
if [ -n "${JAVA_HOME:-}" ]; then PATH="$JAVA_HOME/bin:$PATH"; export JAVA_HOME PATH; fi

# --- locate zap.sh --------------------------------------------------------
if [ -z "${ZAP_SH:-}" ]; then
  for d in "$HOME/.local/opt"/ZAP_* "/Applications/ZAP.app/Contents/Java"; do
    if [ -x "$d/zap.sh" ]; then ZAP_SH="$d/zap.sh"; fi
  done
fi
if [ -z "${ZAP_SH:-}" ] || [ ! -x "$ZAP_SH" ]; then
  echo "zap-native: zap.sh not found — install ZAP or set ZAP_SH" >&2
  exit 127
fi

# --- translate the adapter's flags ---------------------------------------
url=""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -t) url="$2"; shift 2 ;;
    -J) out="$2"; shift 2 ;;
    -I) shift ;;
    *)  shift ;;
  esac
done
if [ -z "$url" ]; then echo "zap-native: no target (-t) given" >&2; exit 2; fi
[ -n "$out" ] || out="/tmp/cosentinel-zap.json"

# -silent: never phone home for add-on updates during a scan.
exec "$ZAP_SH" -cmd -silent -quickurl "$url" -quickout "$out" -quickprogress
