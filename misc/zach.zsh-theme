# Functions for command execution time
function preexec {
  timer=$SECONDS
}

function precmd {
  if [[ -n $timer ]]; then
    local elapsed=$(( SECONDS - timer ))
    if [[ $elapsed -gt 5 ]]; then
      print -P "${PR_YELLOW}Last command took ${elapsed} seconds.${PR_RESET}"
    fi
    unset timer
  fi
}

autoload -U add-zsh-hook
add-zsh-hook preexec preexec
add-zsh-hook precmd precmd

# Remove ASCII art code as per your update
# (No code related to ASCII art)

function theme_precmd {
  local TERMWIDTH=$(( COLUMNS - ${ZLE_RPROMPT_INDENT:-1} ))

  PR_FILLBAR=""
  PR_PWDLEN=""

  local promptsize=${#${(%):---(%n@%m:%l)---()--}}
  local rubypromptsize=${#${(%)$(ruby_prompt_info)}}
  local pwdsize=${#${(%):-%~}}

  # Truncate the path if it's too long.
  if (( promptsize + rubypromptsize + pwdsize > TERMWIDTH )); then
    (( PR_PWDLEN = TERMWIDTH - promptsize ))
  elif [[ "${langinfo[CODESET]}" = UTF-8 ]]; then
    PR_FILLBAR="\${(l:$(( TERMWIDTH - (promptsize + rubypromptsize + pwdsize) ))::${PR_HBAR}:)}"
  else
    PR_FILLBAR="${PR_SHIFT_IN}\${(l:$(( TERMWIDTH - (promptsize + rubypromptsize + pwdsize) ))::${altchar[q]:--}:)}${PR_SHIFT_OUT}"
  fi
}

function theme_preexec {
  setopt local_options extended_glob
  if [[ "$TERM" = "screen" ]]; then
    local CMD=${1[(wr)^(*=*|sudo|-*)]}
    echo -n "\ek$CMD\e\\"
  fi
}

autoload -U add-zsh-hook
add-zsh-hook precmd theme_precmd
add-zsh-hook preexec theme_preexec

# Set the prompt

# Need this so the prompt will work.
setopt prompt_subst

# Enable colors
autoload -U colors && colors

# Define color variables
PR_RESET="%f%b%k"            # Reset foreground, bold, background
PR_BOLD_GREEN="%B%F{green}"  # Bold green
PR_GREEN="%F{green}"         # Green
PR_CYAN="%F{cyan}"           # Cyan
PR_BOLD_CYAN="%B%F{cyan}"    # Bold cyan
PR_YELLOW="%F{yellow}"       # Yellow
PR_MAGENTA="%F{magenta}"     # Magenta

# Use bold green for the info line
INFO_COLOR="${PR_BOLD_GREEN}"
# Use bold cyan for the PWD
PWD_COLOR="${PR_BOLD_CYAN}"
# Use green for the prompt symbol
PROMPT_SYMBOL_COLOR="${PR_GREEN}"

# Fetch external IP address (cached for 5 minutes)
cache_file="$HOME/.external_ip_cache"
cache_duration=300  # Cache duration in seconds (e.g., 5 minutes)

if [[ -f "$cache_file" ]]; then
  if [[ "$(uname)" = "Darwin" ]]; then
    cache_mod_time=$(stat -f %m "$cache_file")
  else
    cache_mod_time=$(stat -c %Y "$cache_file")
  fi
  if (( $(date +%s) - cache_mod_time < cache_duration )); then
    EXTERNAL_IP=$(cat "$cache_file")
  else
    EXTERNAL_IP=$(curl -s ifconfig.me || echo "Unavailable")
    echo "$EXTERNAL_IP" > "$cache_file"
  fi
else
  EXTERNAL_IP=$(curl -s ifconfig.me || echo "Unavailable")
  echo "$EXTERNAL_IP" > "$cache_file"
fi
export EXTERNAL_IP

# Modify Git prompt with enhanced status indicators
ZSH_THEME_GIT_PROMPT_PREFIX="%F{green}on "
ZSH_THEME_GIT_PROMPT_SUFFIX="%f"
ZSH_THEME_GIT_PROMPT_DIRTY="%F{red} ✗%f"
ZSH_THEME_GIT_PROMPT_CLEAN="%F{green} ✔%f"

# Enhanced Git status symbols
ZSH_THEME_GIT_PROMPT_ADDED="%F{green}✚%f"       # Added
ZSH_THEME_GIT_PROMPT_MODIFIED="%F{blue}✹%f"     # Modified
ZSH_THEME_GIT_PROMPT_DELETED="%F{red}✖%f"       # Deleted
ZSH_THEME_GIT_PROMPT_RENAMED="%F{magenta}➜%f"   # Renamed
ZSH_THEME_GIT_PROMPT_UNMERGED="%F{yellow}═%f"   # Unmerged
ZSH_THEME_GIT_PROMPT_UNTRACKED="%F{cyan}✭%f"    # Untracked
ZSH_THEME_GIT_PROMPT_STASHED="%F{yellow}⚑%f"    # Stashed
ZSH_THEME_GIT_PROMPT_CLEAN="%F{green}✔%f"       # Clean

# Finally, set the prompt
PROMPT='${INFO_COLOR}%n@%m (${EXTERNAL_IP}) - %D{%Y-%m-%d} - %D{%H:%M:%S}%{$reset_color%}
${PR_GREEN}$(git_prompt_info)$(git_prompt_status) ${PWD_COLOR}%~${PR_RESET} ${PROMPT_SYMBOL_COLOR}>${PR_RESET} '

# Display exit code on the right when > 0
return_code='%(?..%F{red}%? ↵%f)'
RPROMPT='${return_code}'

PS2='${PROMPT_SYMBOL_COLOR}>${PR_RESET} '
