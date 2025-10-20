# --- Session Logging Plugin (Zsh) -------------------------------------------
# Drop this file somewhere (e.g., ~/.config/zsh/session-logging.zsh) and source
# it from your .zshrc:  source ~/.config/zsh/session-logging.zsh
#
# Key features
# - Starts a recorded login shell under `script`, only in interactive TTYs
# - Cross-platform `script` flags (BSD/macOS vs util-linux)
# - Robust locking (flock when available, PID lock fallback)
# - XDG-friendly default log dir (~/.local/state/terminal_logs)
# - Secure perms; rotates/prunes old logs; optional timing for scriptreplay
# - Helpers: loggrep, loggrep_past, logfind, loggrep_tmux, logcurrent
# - Opt-out/in via env vars; avoids re-entry and recursive searches

# --------------------------- Config (override before sourcing) ---------------
: "${SCRIPT_LOG_DIR:=${XDG_STATE_HOME:-$HOME/.local/state}/terminal_logs}"
: "${SCRIPT_LOG_BASENAME:=terminal}"
: "${SCRIPT_LOG_LOCKFILE:=$HOME/.script_logging.lock}"
: "${SCRIPT_LOG_KEEP:=50}"            # how many logs to keep
: "${SCRIPT_LOG_TIMING:=1}"           # 1 = also write .timing for scriptreplay
: "${FORCE_SESSION_LOGGING:=0}"       # 1 = force even in non-login/non-tty shells
: "${DISABLE_SESSION_LOGGING:=0}"     # 1 = disable entirely

# --------------------------- Helper functions (always defined) --------------
# These do not depend on startup state; they read env at call-time.
# Flexible loggrep: supports -A/-B/-C anywhere (before or after the pattern)
# Flexible loggrep: heading mode by default, context flags anywhere
loggrep() {
  emulate -L zsh
  setopt no_aliases no_bang_hist no_glob

  # Allow multiple dirs via colon-separated env; include legacy ~/terminal_logs
  local raw_dirs="${SCRIPT_LOG_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/terminal_logs}"
  raw_dirs="${raw_dirs}:$HOME/terminal_logs"
  local -a dirs uniq_dirs
  IFS=: read -rA dirs <<< "$raw_dirs"
  # de-dup & keep existing ones
  typeset -A seen
  for d in "${dirs[@]}"; do
    [[ -n "$d" && -d "$d" && -z ${seen[$d]} ]] && { uniq_dirs+=("$d"); seen[$d]=1; }
  done
  (( ${#uniq_dirs} )) || { print -u2 "loggrep: no log dirs found"; return 1; }

  (( $# )) || { print -u2 "usage: loggrep <pattern> [flags]"; return 2; }

  # Separate options anywhere (-A/-B/-C, etc.) from the pattern (join multi-word)
  local -a pre_opts post_opts patterns
  local i=1 arg next
  while (( i <= $# )); do
    arg="${@[$i]}"
    if (( ${#patterns} == 0 )); then
      if [[ $arg == -* ]]; then
        pre_opts+="$arg"
        [[ $arg == (-A|-B|-C|--context) && $((i+1)) -le $# ]] && { next="${@[$((i+1))]}"; pre_opts+="$next"; ((i++)); }
      else
        patterns+="$arg"
      fi
    else
      if [[ $arg == (-A|-B|-C|--after-context=*|--before-context=*|--context=*|--context) ]]; then
        post_opts+="$arg"
        [[ $arg == (-A|-B|-C|--context) && $((i+1)) -le $# ]] && { next="${@[$((i+1))]}"; post_opts+="$next"; ((i++)); }
      else
        patterns+="$arg"
      fi
    fi
    ((i++))
  done
  local pattern="${(j: :)patterns}"

  # clean break from any noisy prompt hook
  print -r -- ""

  if command -v rg >/dev/null 2>&1; then
    # Exclude live/current, latest symlink, timing files
    local -a globs
    [[ -n ${CURRENT_SESSION_LOG_BASENAME-} ]] && globs+=("--glob=!${CURRENT_SESSION_LOG_BASENAME}")
    globs+=("--glob=!${SCRIPT_LOG_BASENAME:-terminal}-latest.log" "--glob=!*.timing")
    # Search all dirs
    rg -n --heading --hidden --follow \
       "${pre_opts[@]}" "${post_opts[@]}" "${globs[@]}" \
       -e "$pattern" -- "${uniq_dirs[@]}"
  else
    # find+grep over all dirs
    local -a find_expr_base=(-type f -name '*.log' ! -name "${SCRIPT_LOG_BASENAME:-terminal}-latest.log" ! -name '*.timing')
    local -a files
    for d in "${uniq_dirs[@]}"; do
      while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$d" "${find_expr_base[@]}" -print0)
    done
    # Exclude current live file if it exists
    if [[ -n ${CURRENT_SESSION_LOG-} && -e ${CURRENT_SESSION_LOG-} ]]; then
      local -a files2; for f in "${files[@]}"; do [[ ! "$f" -ef "$CURRENT_SESSION_LOG" ]] && files2+=("$f"); done; files=("${files2[@]}")
    fi
    (( ${#files} )) || { print -u2 "loggrep: no log files found"; return 1; }
    printf '%s\0' "${files[@]}" | xargs -0 grep -nH --binary-files=text "${pre_opts[@]}" "${post_opts[@]}" -e "$pattern" \
      | awk -F: 'BEGIN{prev=""}{file=$1; line=$2; text=substr($0, index($0,$3)); if(file!=prev){if(prev!="")print "--"; print file ":"; prev=file} print line ":" text} END{if(NR>0)print "--"}'
  fi
}




loggrep_past() {
  # Search only logs older than this shell's start time
  local dir="${SCRIPT_LOG_DIR}"; local start="${SESSION_START_EPOCH:-0}"
  if [[ $# -eq 0 ]]; then print -u2 "usage: loggrep_past <pattern> [grep flags…]"; return 2; fi
  if command -v rg >/dev/null 2>&1; then
    local -a globs
    [[ -n ${CURRENT_SESSION_LOG_BASENAME-} ]] && globs+=("--glob=!$CURRENT_SESSION_LOG_BASENAME")
    globs+=("--glob=!${SCRIPT_LOG_BASENAME}-latest.log" "--glob=!*\.timing" )
    rg -n --no-heading --hidden --follow --max-filesize 100M "${globs[@]}" -- "$@" "$dir" \
      | awk -v start="$start" -F: '{ cmd = "stat -c %Y \""$1"\" 2>/dev/null"; cmd | getline m; close(cmd); if (m!="" && m < start) print $0 }'
    return $?
  fi
  # Fallback: find + grep
  local -a find_expr=(-type f -name '*.log')
  if [[ -n ${CURRENT_SESSION_LOG-} && -e ${CURRENT_SESSION_LOG-} ]]; then
    find_expr+=( ! -samefile "$CURRENT_SESSION_LOG" )
  fi
  find_expr+=( ! -name "${SCRIPT_LOG_BASENAME}-latest.log" ! -name '*.timing' -not -newermt "@${start}" )
  find "$dir" "${find_expr[@]}" -print0 | xargs -0 grep -nH --binary-files=text -- "$@"
}

logfind() {
  # List session logs newest-first
  local dir="${SCRIPT_LOG_DIR}"
  ls -1t -- "$dir"/*.log 2>/dev/null | sed "s|$dir/||"
}

loggrep_tmux() {
  # Run ripgrep in a tmux popup that is NOT logged
  if ! command -v tmux >/dev/null 2>&1; then print -u2 "tmux not found"; return 1; fi
  if ! command -v rg >/dev/null 2>&1; then print -u2 "rg (ripgrep) required"; return 1; fi
  local pattern="$1"; shift || true
  local dir="${SCRIPT_LOG_DIR}"
  local gl="--glob=!${CURRENT_SESSION_LOG_BASENAME:-__none__} --glob=!${SCRIPT_LOG_BASENAME}-latest.log --glob=!*\.timing"
  tmux display-popup -E "DISABLE_SESSION_LOGGING=1 rg -n --no-heading $gl -- '$pattern' '$dir' | less -R"
}

logcurrent() { print -r -- "${CURRENT_SESSION_LOG:-(none)}"; }

# --------------------------- Startup logic (separate) -----------------------
# We keep helpers available even when we skip starting the recorder.
_start_session_logging() {
  # Quick exits / guards — BUT do not prevent helper definitions.
  # Already running in a logged session? (avoid nesting the recorder)
  [[ -n ${SESSION_LOGGING-} ]] && return 0
  # Hard opt-out
  [[ $DISABLE_SESSION_LOGGING = 1 ]] && return 0
  # Only interactive terminals unless forced
  if [[ $FORCE_SESSION_LOGGING != 1 ]]; then
    [[ -o interactive ]] || return 0
    [[ -t 0 && -t 1 && -t 2 ]] || return 0
  fi
  # Require `script`
  if ! command -v script >/dev/null 2>&1; then
    print -u2 "[session-logging] 'script' not found; skipping."
    return 0
  fi

  # Filesystem prep
  umask 077
  mkdir -p -- "$SCRIPT_LOG_DIR" 2>/dev/null || {
    print -u2 "[session-logging] cannot create $SCRIPT_LOG_DIR"
    return 0
  }
  chmod 700 -- "$SCRIPT_LOG_DIR" 2>/dev/null || true

  # Filename construction
  local _timestamp _user _host _tty _shell
  _timestamp=$(date +"%Y%m%d-%H%M%S")
  _user=${USER:-unknown}
  _host=$(hostname -s 2>/dev/null || print -r -- host)
  _tty=$(basename -- "${TTY:-tty}")
  _shell=$(basename -- "${SHELL:-zsh}")

  local _logfile _timingfile
  _logfile="$SCRIPT_LOG_DIR/${SCRIPT_LOG_BASENAME}-${_timestamp}-${_user}@${_host}-${_shell}-${_tty}.log"
  _timingfile="${_logfile%.log}.timing"

  # Export for helpers and child shell
  export CURRENT_SESSION_LOG="$_logfile"
  export CURRENT_SESSION_LOG_BASENAME="${_logfile##*/}"
  export SESSION_START_EPOCH="$(date +%s)"

  # Feature detection
  local _SUPPORTS_F=0
  script -q -f /dev/null -c true >/dev/null 2>&1 && _SUPPORTS_F=1
  local _TIMING_MODE=none
  if script -q -t "$_timingfile" /dev/null -c true >/dev/null 2>&1; then
    _TIMING_MODE=file
  fi

  local -a _script_args; _script_args=(-q)
  [[ $_SUPPORTS_F = 1 ]] && _script_args+=(-f)
  local -a _timing_args
  if [[ $SCRIPT_LOG_TIMING = 1 && $_TIMING_MODE = file ]]; then
    _timing_args=(-t "$_timingfile")
  fi

  # Locking & rotation
  local _have_flock=0; command -v flock >/dev/null 2>&1 && _have_flock=1
  _acquire_lock() {
    if [[ $_have_flock = 1 ]]; then
      exec {__LOCKFD}>"$SCRIPT_LOG_LOCKFILE" || return 1
      flock -n "$__LOCKFD" || return 1
      print -u "$__LOCKFD" "$" >/dev/null 2>&1 || true
    else
      if [[ -f "$SCRIPT_LOG_LOCKFILE" ]]; then
        local _lockpid; _lockpid=$(<"$SCRIPT_LOG_LOCKFILE" 2>/dev/null || true)
        if [[ -n $_lockpid ]] && ! kill -0 "$_lockpid" 2>/dev/null; then
          rm -f -- "$SCRIPT_LOG_LOCKFILE"
        else
          return 1
        fi
      fi
      print -r -- "$$" >| "$SCRIPT_LOG_LOCKFILE" || return 1
    fi
  }
  _release_lock() { rm -f -- "$SCRIPT_LOG_LOCKFILE" 2>/dev/null || true }
  _prune_logs() {
    local _pattern="$SCRIPT_LOG_DIR/${SCRIPT_LOG_BASENAME}-*.log"; local -a files; files=(${~_pattern})
    (( ${#files} > SCRIPT_LOG_KEEP )) || return 0
    printf '%s
' "${files[@]}" | sort | head -n "$(( ${#files} - SCRIPT_LOG_KEEP ))" | xargs -r rm -f --
    printf '%s
' "${files[@]/%.log/.timing}" | xargs -r rm -f -- 2>/dev/null
  }

  if ! _acquire_lock; then
    # Another session already logging; skip starting a nested recorder
    return 0
  fi

  # Mark env for this process tree
  export SESSION_LOGGING=1

  # Convenience symlink to most recent log (best-effort)
  ln -sf -- "$_logfile" "$SCRIPT_LOG_DIR/${SCRIPT_LOG_BASENAME}-latest.log" 2>/dev/null || true

  # Cleanup on exit
  _cleanup_logging() { _release_lock; _prune_logs; }
  for _sig in EXIT HUP INT TERM; do trap _cleanup_logging "$_sig"; done
  unset _sig

  # Launch a login shell under `script` (replace current shell)
  exec script "${_script_args[@]}" "${_timing_args[@]}" "$_logfile" -c "${SHELL:-/bin/zsh} -l"
}

# Kick off logging for this shell (helpers are already available)
_start_session_logging
# ---------------------------------------------------------------------------
