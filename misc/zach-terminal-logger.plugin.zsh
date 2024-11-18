# Path to the lock file
export SCRIPT_LOGGING_LOCKFILE="$HOME/.script_logging.lock"

# Function to check if we're already logging
function start_logging() {
  # If the lock file exists, we're already logging
  if [[ -f "$SCRIPT_LOGGING_LOCKFILE" ]]; then
    return
  else
    # Create the lock file
    touch "$HOME/.script_logging.lock"

    # Create logs directory if it doesn't exist
    mkdir -p "$HOME/terminal_logs"

    # Generate a unique filename with timestamp and PID
    timestamp=$(date +"%Y%m%d-%H%M%S")
    logfile="$HOME/terminal_logs/terminal-$timestamp-$$.log"

    # Detect the operating system
    case "$(uname)" in
      Darwin)
        # macOS
        exec script -q "$logfile"
        ;;
      Linux)
        # Linux (including Kali Linux)
        exec script -q -f "$logfile"
        ;;
      *)
        # Other Unix-like systems
        exec script -q "$logfile"
        ;;
    esac
  fi
}

# Start logging
start_logging

# Remove the lock file when exiting the shell
function remove_lockfile() {
  rm -f "$HOME/.script_logging.lock"
}

# Ensure the lock file is removed upon shell exit
trap remove_lockfile EXIT
