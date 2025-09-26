#!/usr/bin/env bash
#
# hc-auto.sh - small wrapper to automate common hashcat workflows
# Usage examples below. Read the comments and --help output.
#
# Requirements:
# - hashcat installed and in PATH
# - optional: hashid or hash-identifier for better detection (script will detect heuristically if not present)
#

set -euo pipefail
IFS=$'\n\t'

VERSION="1.0"

# Default options
HASHFILE=""
ATTACK="wordlist"    # wordlist|mask|rule|combinator
WORDLIST="/usr/share/wordlists/rockyou.txt"
MASK="?l?l?l?l?d?d"
RULEFILE=""
COMBINATOR_LIST=""
OUTDIR="./hc-output"
SESSION=""
MODE=""  # explicit hashcat -m code if provided
THREADS=""
RESTORE=false
SHOW=false
FORCE=false

# Heuristic detection map (very basic). If ambiguous, script will ask user to provide -m.
declare -A HEURISTIC_MAP
HEURISTIC_MAP["^\\$2[aby]\\$[0-9]{2}\\$"]="3200"       # bcrypt
HEURISTIC_MAP["^\\$1\\$"]="500"                        # MD5crypt
HEURISTIC_MAP["^\\$5\\$"]="7400"                      # SHA256crypt
HEURISTIC_MAP["^\\$6\\$"]="1800"                      # SHA512crypt
HEURISTIC_MAP["^[0-9a-fA-F]{32}$"]="0"                # MD5 / also NTLM ambiguous
HEURISTIC_MAP["^[0-9a-fA-F]{40}$"]="100"              # SHA1
HEURISTIC_MAP["^[0-9a-fA-F]{64}$"]="1400"             # SHA256
HEURISTIC_MAP["^[0-9a-fA-F]{128}$"]="1700"            # SHA512
HEURISTIC_MAP["^[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}$"]="5500" # NetNTLMv1 (example pattern; adapt as needed)

usage() {
  cat <<EOF
hc-auto.sh v$VERSION — simple hashcat helper

Usage: $0 [options]

Options:
  -f, --hashfile PATH     Path to file containing hashes (one per line). REQUIRED.
  -m, --mode CODE         hashcat -m mode code (if you already know it)
  -a, --attack TYPE       Attack type: wordlist (default), mask, rule, combinator
  -w, --wordlist PATH     Wordlist path (default: $WORDLIST)
  -k, --mask MASK         Mask string for mask attack (default: $MASK)
  -r, --rule FILE         Rule file to use (enables rule attack)
  -c, --combinator LIST   Combinator list (file) for combinator attack
  -s, --session NAME      Session name for hashcat (--session)
  -o, --outdir DIR        Directory to store outputs (default: $OUTDIR)
  --restore               Restore previous session (uses --session)
  --show                  After the run, show cracked hashes and save to file
  --force                 Pass --force to hashcat (use only if you understand the risk)
  -h, --help              Show this help

Examples:
  # wordlist attack (default)
  $0 -f hashes.txt -w /path/to/wordlist.txt

  # mask attack
  $0 -f hashes.txt -a mask -k '?l?l?l?l?d?d'

  # known mode (NTLM = 1000)
  $0 -f hashes.txt -m 1000 -w rockyou.txt

  # resume a session
  $0 -s mysess --restore

EOF
}

# Simple logger
log() { echo "[*] $*"; }
err() { echo "[!] $*" >&2; }

# parse args (basic)
ARGS=()
while (( "$#" )); do
  case "$1" in
    -f|--hashfile) HASHFILE="$2"; shift 2;;
    -m|--mode) MODE="$2"; shift 2;;
    -a|--attack) ATTACK="$2"; shift 2;;
    -w|--wordlist) WORDLIST="$2"; shift 2;;
    -k|--mask) MASK="$2"; shift 2;;
    -r|--rule) RULEFILE="$2"; shift 2;;
    -c|--combinator) COMBINATOR_LIST="$2"; shift 2;;
    -s|--session) SESSION="$2"; shift 2;;
    -o|--outdir) OUTDIR="$2"; shift 2;;
    --restore) RESTORE=true; shift;;
    --show) SHOW=true; shift;;
    --force) FORCE=true; shift;;
    -h|--help) usage; exit 0;;
    --version) echo "$VERSION"; exit 0;;
    --) shift; break;;
    -*|--*=) err "Unknown option $1"; usage; exit 1;;
    *) ARGS+=("$1"); shift;;
  esac
done

# Validate basic inputs
if [[ -z "$HASHFILE" && "$RESTORE" = false ]]; then
  err "Hashfile is required (use -f)."
  usage
  exit 2
fi

if [[ "$RESTORE" = true && -z "$SESSION" ]]; then
  err "--restore requires a session name (-s/--session)."
  exit 2
fi

mkdir -p "$OUTDIR"

# detect_hash: try hashid if installed, otherwise heuristic
detect_hash() {
  local sample first nonblank mode_guess=""
  sample=$(grep -v '^\s*$' "$HASHFILE" | head -n 10 | tr -d '\r' | head -n1 || true)
  if [[ -z "$sample" ]]; then
    err "Hashfile seems empty or unreadable."
    exit 3
  fi

  if command -v hashid >/dev/null 2>&1; then
    log "Using hashid to detect hash type..."
    # hashid outputs human readable; we try to extract known mode via heuristic mapping (not perfect)
    # We simply return empty here to encourage user to pass -m if ambiguous.
    command -v jq >/dev/null 2>&1 || true
    # keep simple: run hashid and show to user, then exit with suggestion
    hashid "$sample" || true
    echo ""
    echo "hashid output shown above. If the mapping to hashcat -m is ambiguous, re-run with -m <code>."
    return 0
  fi

  # heuristic fallback
  for pat in "${!HEURISTIC_MAP[@]}"; do
    if [[ $sample =~ $pat ]]; then
      mode_guess="${HEURISTIC_MAP[$pat]}"
      echo "$mode_guess"
      return 0
    fi
  done

  # special-case: if sample contains ":" treat as candidate for complex formats
  if [[ "$sample" == *:* ]]; then
    # many complex formats; prefer user to specify
    echo ""
    return 0
  fi

  echo ""
  return 0
}

# Build hashcat command
build_cmd() {
  local cmd=(hashcat)

  # session
  [[ -n "$SESSION" ]] && cmd+=(--session "$SESSION")

  [[ "$FORCE" = true ]] && cmd+=(--force)

  # output dir + files
  cmd+=(--outfile-format 2) # 2 = plain: hash:plain? (note: different formats available)
  OUTFILE="$OUTDIR/cracked.txt"
  cmd+=(--outfile "$OUTFILE")
  cmd+=(--potfile-path "$OUTDIR/hashcat.potfile")

  # speedup options could be added here (e.g. -w 3 -O) but left conservative

  # threads/other opts
  [[ -n "$THREADS" ]] && cmd+=(-T "$THREADS")

  # mode
  if [[ -n "$MODE" ]]; then
    cmd+=(-m "$MODE")
  fi

  # attack mode
  case "$ATTACK" in
    wordlist)
      cmd+=(-a 0) # straight
      cmd+=("$HASHFILE" "$WORDLIST")
      ;;
    mask)
      cmd+=(-a 3) # mask
      cmd+=("$HASHFILE" "$MASK")
      ;;
    rule)
      if [[ -z "$RULEFILE" ]]; then err "Rule attack requires -r RULEFILE"; exit 2; fi
      cmd+=(-a 0 "$HASHFILE" "$WORDLIST" -r "$RULEFILE")
      ;;
    combinator)
      if [[ -z "$COMBINATOR_LIST" ]]; then err "Combinator attack requires -c COMBINATOR_LIST"; exit 2; fi
      cmd+=(-a 1 "$HASHFILE" "$COMBINATOR_LIST" "$WORDLIST")
      ;;
    *)
      err "Unknown attack type: $ATTACK"
      exit 2
      ;;
  esac

  echo "${cmd[@]}"
}

# If restore, run restore
if [[ "$RESTORE" = true ]]; then
  log "Restoring session '$SESSION'..."
  if [[ -n "$MODE" ]]; then
    log "Note: you provided -m $MODE for restore."
  fi
  # Run hashcat --restore --session <session>
  RUNCMD=(hashcat --session "$SESSION" --restore)
  log "Running: ${RUNCMD[*]}"
  "${RUNCMD[@]}"
  if [[ "$SHOW" = true ]]; then
    log "Collecting cracked hashes to $OUTDIR/cracked_${SESSION}.txt"
    hashcat --session "$SESSION" --show --potfile-path "$OUTDIR/hashcat.potfile" > "$OUTDIR/cracked_${SESSION}.txt" || true
    log "Saved: $OUTDIR/cracked_${SESSION}.txt"
  fi
  exit 0
fi

# If user didn't pass explicit mode, try to detect
if [[ -z "$MODE" ]]; then
  log "Attempting to detect hash type heuristically..."
  MODE_DETECTED=$(detect_hash)
  if [[ -z "$MODE_DETECTED" ]]; then
    log "Could not unambiguously detect a hashcat mode for the given sample(s)."
    log "Please re-run with -m <mode> (hashcat mode code). Known common values: 0=MD5,100=SHA1,1400=SHA256,1700=SHA512,1000=NTLM,3200=bcrypt"
    exit 0
  else
    MODE="$MODE_DETECTED"
    log "Heuristic selected hashcat mode: $MODE (you can override with -m)."
  fi
fi

# final build and run
CMD_STR=$(build_cmd)
log "Final hashcat command:"
echo "$CMD_STR"
# convert string to array safely (preserve quotes)
eval "CMD=($CMD_STR)"

log "Starting hashcat..."
"${CMD[@]}"

# After run: optionally show cracked results
if [[ "$SHOW" = true ]]; then
  FINAL_OUT="$OUTDIR/cracked_$(date +%Y%m%d_%H%M%S).txt"
  log "Saving cracked hashes (hash:plain) to $FINAL_OUT"
  # use --show reading same potfile path
  hashcat --show -m "$MODE" "$HASHFILE" --potfile-path "$OUTDIR/hashcat.potfile" > "$FINAL_OUT" || true
  log "Saved: $FINAL_OUT"
fi

log "Done."
