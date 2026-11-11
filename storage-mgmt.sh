#!/bin/sh
################################################################################
# PowerScale Storage Management Script
#
# This script manages PowerScale cluster operations including:
# - Node removal (smartfail)
# - Node addition
# - Node pool carving
# - Node neighborhood listing
# - Nodepool removal
#
# Author: Elie Koivunen (Elie.Koivunen@dell.com)
# Version: 1.2.8
# License: MIT
#
# Future enhancements
#   - add mechanism to check node state after joining a cluster
#
# CHANGELOG:
#   1.2.8 - Obfuscated Python code in list_neighborhoods function using base64 encoding
#           Makes it less obvious that Python is being used for neighborhood listing
#   1.2.7 - Added --healthcheck switch for --nodes-add operation
#           Runs battery test and readonly mode checks after each node joins
#           Checks occur before proceeding to add the next node
#           Requires user intervention if checks fail (unless --force is used)
#   1.2.6 - Added --verbose switch to enable debug output for troubleshooting
#           DEBUG messages only display when --verbose is enabled
#   1.2.5 - Added --force switch to skip user confirmation prompts
#           When --force is used, script proceeds without asking for confirmation
#   1.2.4 - Added optional --nodepool-name= switch for custom nodepool naming
#           Accepts alphanumeric and dash names up to 34 characters
#           Defaults to CARVEDPOOL-XXX if not provided
#   1.2.3 - Added timestamp suffix to all log- and mgmt- files for better tracking
#           Files now named: log-nodes-removed_YYYYMMDD_HHMMSS.txt, etc.
#   1.2.2 - Moved all log files and temporary files to logs_storage-mgmt directory
#           Renamed logs folder to logs_storage-mgmt for better organization
#   1.2.1 - Fixed simultaneous smartfail in --nodepool-remove to execute both commands
#           separately with proper logging (was using && which caused issues)
#   1.2.0 - Aligned with v0.70 procedure for wait logic and sanity checks
#           - Changed wait time from 60s to 900s (15 minutes) per check
#           - Removed timeout limits (wait indefinitely like v0.70)
#           - Added timestamp logging for status checks
#           - Added 5-minute grace period before node addition (v0.70)
#           - Improved manual override logic to check current state first
#           - Added comments documenting v0.70 procedures for future reference
#   1.1.9 - Revised --nodes-remove and --nodepool-remove to wait for nodes to appear
#           in isi devices node list after smartfail (not disappear)
#   1.1.8 - Removed --config switch and load_config function (not needed)
#   1.1.7 - Fixed cleanup function to handle early exit cases (e.g., --help)
#           Prevents error when LOG_FILE is not initialized
#   1.1.6 - Enhanced serial display to show full node details from isi devices node list
#   1.1.5 - Added display of serials to be added before user confirmation
#   1.1.4 - Fixed serial number validation to allow hyphens in serials
#           Updated regex to accept format: SV200-000NZS-YNIB
#   1.1.3 - Reverted pool mode switching - confirmed manual pools cannot be carved
#           Sanity check: exit if source pool is Manual: Yes
#   1.1.2 - Added automatic pool mode switching for carving operations (reverted)
#   1.1.1 - Fixed pool mode check logic to correctly block auto-managed pools
#           and allow manual pools for carving operations
#   1.1.0 - Added --nodepool-remove switch to remove all nodes from a nodepool
#           Nodes are smartfailed in reverse order, last two simultaneously
#   1.0.1 - Removed --dry-run and --verbose options, converted to POSIX sh
#   1.0.0 - Critical bug fixes, added dry-run mode, pre-flight validation,
#           improved error handling, configurable parameters, trap handler,
#           lock file mechanism, comprehensive logging, progress indication
#   0.70  - Added node model listing when identifying nodes to remove
################################################################################

set -u          # Exit on undefined variables
set -e          # Exit on error

################################################################################
# Configuration and Metadata
################################################################################

SCRIPT_VERSION="1.2.8"
SCRIPT_DATE="2026-11-09"
SCRIPT_AUTHOR="Elie Koivunen"
SCRIPT_EMAIL="Elie.Koivunen@dell.com"
SCRIPT_LICENSE="MIT"

# Default configuration
DEFAULT_SLEEP_SHORT=300      # 5 minutes
DEFAULT_SLEEP_LONG=900       # 15 minutes
DEFAULT_WAIT_CHECK=900       # 15 minutes (v0.70 wait time)
DEFAULT_MIN_POOL_NODES=3     # Minimum nodes to remain in pool
DEFAULT_MIN_CARVE_NODES=3    # Minimum nodes to carve
DEFAULT_LOCK_FILE="/tmp/storage-mgmt.lock"
DEFAULT_LOG_DIR="./logs_storage-mgmt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Global Variables
################################################################################

SCRIPT_PATH=$(cd "$(dirname "$0")" && pwd)
LOG_FILE=""
LOCK_FILE="${DEFAULT_LOCK_FILE}"

# Runtime variables
REMOVE_NODES_LNN=""
ADD_NODES_SERIALS=""
CARVE_NODES_LNN=""
REMOVE_NODEPOOL=""
CARVE_NODEPOOL_NAME=""
FORCE=false
VERBOSE=false
HEALTHCHECK=false

################################################################################
# Logging Functions
################################################################################

# Initialize logging
init_logging() {
    LOG_DIR="${1:-${DEFAULT_LOG_DIR}}"

    # Debug: Show what LOG_DIR is set to
    if [ "${VERBOSE}" = true ]; then
        echo "DEBUG: LOG_DIR set to: ${LOG_DIR}" >&2
    fi

    # Create log directory if it doesn't exist
    if [ ! -d "${LOG_DIR}" ]; then
        mkdir -p "${LOG_DIR}" || {
            echo "ERROR: Failed to create log directory: ${LOG_DIR}" >&2
            exit 1
        }
    fi

    # Create log file with timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    LOG_FILE="${LOG_DIR}/storage-mgmt_${timestamp}.log"

    echo "=== Storage Management Script v${SCRIPT_VERSION} ===" > "${LOG_FILE}"
    echo "Started: $(date)" >> "${LOG_FILE}"
    echo "Running on: $(hostname)" >> "${LOG_FILE}"
    echo "User: $(whoami)" >> "${LOG_FILE}"
    echo "" >> "${LOG_FILE}"
}

# Log message with level
log() {
    level="$1"
    shift
    message="$*"
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"

    case "${level}" in
        ERROR)
            printf '%b\n' "${RED}[ERROR]${NC} ${message}" >&2
            ;;
        WARN)
            printf '%b\n' "${YELLOW}[WARN]${NC} ${message}" >&2
            ;;
        INFO)
            printf '%b\n' "${GREEN}[INFO]${NC} ${message}" >&2
            ;;
        DEBUG)
            if [ "${VERBOSE}" = true ]; then
                printf '%b\n' "${BLUE}[DEBUG]${NC} ${message}" >&2
            fi
            ;;
    esac
}

# Log and execute command
log_exec() {
    cmd="$*"
    log INFO "Executing: ${cmd}"

    eval "${cmd}"
    exit_code=$?

    if [ ${exit_code} -ne 0 ]; then
        log ERROR "Command failed with exit code ${exit_code}: ${cmd}"
        return ${exit_code}
    fi

    return 0
}

################################################################################
# Utility Functions
################################################################################

# Display usage information
usage() {
    cat << EOF
================================================================================
PowerScale Storage Management Script v${SCRIPT_VERSION}
Author: ${SCRIPT_AUTHOR} (${SCRIPT_EMAIL})
License: ${SCRIPT_LICENSE}
Release Date: ${SCRIPT_DATE}

General disclaimer: Utilize this script at your own responsibility.
Any modifications to the script should be shared back.

================================================================================
Usage: $0 [OPTIONS]

Operations:
  --nodes-remove=LNN1,LNN2,...         Remove nodes with specified LNNs
  --nodes-add=FILE                     Add nodes with serials from file
  --nodepool-carve=LNN1,LNN2,...       Carve nodes into separate nodepool
  --nodepool-name=POOLNAME            Custom name for carved nodepool (alphanumeric and dash, max 34 chars)
  --nodepool-remove=POOLNAME          Remove all nodes from specified nodepool
  --nodepool-list                     Display node neighborhoods

Options:
  --force                              Skip user confirmation prompts
  --verbose                            Enable verbose/debug output
  --healthcheck                        Run additional health checks after node addition
                                      (battery test and readonly mode check)
  --sleep-short=SECONDS                Short sleep duration (default: 300)
  --sleep-long=SECONDS                 Long sleep duration (default: 900)
  --help                               Display this help menu

Examples:
  # Remove nodes
  $0 --nodes-remove=11,10,9,8
  
  # Add nodes from file
  $0 --nodes-add=/path/to/serials.txt
  
  # Carve nodes into separate pool
  $0 --nodepool-carve=4,3,2
  
  # Remove all nodes from a nodepool
  $0 --nodepool-remove=CARVEDPOOL-ezp
  
  # List neighborhoods
  $0 --nodepool-list

Note: All logs and temporary files are stored in ./logs_storage-mgmt/

Run this script in a screen session for long operations!
Example: screen -S storage-mgmt -d -m sh -c "./storage-mgmt.sh --nodes-remove=8,7,6,5"

================================================================================
EOF
}

# Cleanup function for trap handler
cleanup() {
    exit_code=$?

    # Only run cleanup if logging has been initialized
    if [ -n "${LOG_FILE}" ]; then
        log INFO "Cleaning up..."

        # Remove lock file if we own it
        if [ -f "${LOCK_FILE}" ]; then
            lock_pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")
            if [ "${lock_pid}" = "$$" ]; then
                rm -f "${LOCK_FILE}"
                log DEBUG "Removed lock file: ${LOCK_FILE}"
            fi
        fi

        log INFO "Script completed with exit code: ${exit_code}"
        log INFO "Finished: $(date)"
    else
        # Cleanup without logging (for --help case)
        if [ -f "${LOCK_FILE}" ]; then
            lock_pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")
            if [ "${lock_pid}" = "$$" ]; then
                rm -f "${LOCK_FILE}"
            fi
        fi
    fi

    exit ${exit_code}
}

# Set trap handler
trap cleanup EXIT INT TERM

# Acquire lock file
acquire_lock() {
    if [ -f "${LOCK_FILE}" ]; then
        lock_pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")
        if [ -n "${lock_pid}" ] && kill -0 "${lock_pid}" 2>/dev/null; then
            log ERROR "Script is already running (PID: ${lock_pid})"
            exit 1
        else
            log WARN "Removing stale lock file"
            rm -f "${LOCK_FILE}"
        fi
    fi

    echo $$ > "${LOCK_FILE}"
    log DEBUG "Acquired lock: ${LOCK_FILE}"
}

# Validate LNN format
validate_lnn() {
    lnn="$1"

    if ! echo "${lnn}" | grep -qE '^[0-9]+$'; then
        log ERROR "Invalid LNN format: ${lnn} (must be numeric)"
        return 1
    fi

    return 0
}

# Validate serial number format
validate_serial() {
    serial="$1"

    # Serial numbers are typically alphanumeric with hyphens, case-insensitive
    if ! echo "${serial}" | grep -qE '^[A-Za-z0-9-]+$'; then
        log ERROR "Invalid serial format: ${serial}"
        return 1
    fi

    return 0
}

# Validate nodepool name format
validate_nodepool_name() {
    name="$1"

    # Nodepool names must be alphanumeric with hyphens, max 34 characters
    if [ -z "${name}" ]; then
        if [ -n "${LOG_FILE}" ]; then
            log ERROR "Nodepool name cannot be empty"
        else
            echo "ERROR: Nodepool name cannot be empty" >&2
        fi
        return 1
    fi

    if [ ${#name} -gt 34 ]; then
        if [ -n "${LOG_FILE}" ]; then
            log ERROR "Nodepool name exceeds 34 characters: ${name}"
        else
            echo "ERROR: Nodepool name exceeds 34 characters: ${name}" >&2
        fi
        return 1
    fi

    if ! echo "${name}" | grep -qE '^[A-Za-z0-9-]+$'; then
        if [ -n "${LOG_FILE}" ]; then
            log ERROR "Invalid nodepool name format: ${name} (alphanumeric and hyphens only)"
        else
            echo "ERROR: Invalid nodepool name format: ${name} (alphanumeric and hyphens only)" >&2
        fi
        return 1
    fi

    return 0
}

# Pre-flight health check
preflight_check() {
    log INFO "Running pre-flight health checks..."

    # Check if we're on a PowerScale node
    if ! command -v isi > /dev/null 2>&1; then
        log ERROR "isi command not found. This script must run on a PowerScale node."
        return 1
    fi

    # Check cluster health
    log INFO "Checking cluster health..."
    cluster_health=$(isi status | grep -i "cluster health" || echo "unknown")
    log INFO "Cluster health: ${cluster_health}"
    
    # Check for running jobs
    log INFO "Checking for running FlexProtect jobs..."
    running_jobs=$(isi job jobs list | grep -i "flexprotect" | grep -i "running" || echo "")
    if [ -n "${running_jobs}" ]; then
        log WARN "FlexProtect jobs are currently running"
    fi

    # Check node status
    log INFO "Checking node status..."
    down_nodes=$(isi devices node list --no-header --no-footer | grep -i "down" || echo "")
    if [ -n "${down_nodes}" ]; then
        log WARN "Some nodes are in DOWN state"
    fi
    
    log INFO "Pre-flight checks completed"
    return 0
}

################################################################################
# Node Removal Functions
################################################################################

remove_nodes() {
    input="$1"
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Ensure LOG_DIR is set (use default if not)
    LOG_DIR="${LOG_DIR:-${DEFAULT_LOG_DIR}}"
    
    logfile="${LOG_DIR}/log-nodes-removed_${timestamp}.txt"
    removable_file="${LOG_DIR}/mgmt-nodes-removable_${timestamp}.txt"

    log INFO "Starting node removal process"

    # Clean up previous files
    rm -f "${logfile}" "${removable_file}"

    # Parse input
    nodes_input=$(echo "${input}" | sed 's/--nodes-remove=//')
    log INFO "Input nodes: ${nodes_input}"
    
    # Validate input format
    if ! echo "${nodes_input}" | grep -qE '^[0-9,]+$'; then
        log ERROR "Invalid input format. Expected comma-separated LNNs."
        return 1
    fi
    
    # Validate each LNN and collect node information
    node_count=0

    # Use a temporary file to track valid nodes
    temp_nodes_file=$(mktemp)
    echo "${nodes_input}" | tr ',' '\n' > "${temp_nodes_file}"

    while IFS= read -r node; do
        node=$(echo "${node}" | tr -d ' ')
        [ -z "${node}" ] && continue

        if ! validate_lnn "${node}"; then
            continue
        fi

        log INFO "Processing node LNN: ${node}"

        # Get node information
        node_info=$(isi_nodes %{lnn} %{serialno} 2>/dev/null | grep -w "^${node}" || echo "")
        if [ -z "${node_info}" ]; then
            log ERROR "Node LNN ${node} not found in cluster"
            continue
        fi

        # Get node model
        node_model=$(isi_for_array -n${node} "isi_hw_status | egrep 'Product:'" 2>/dev/null | awk '{print $3}' || echo "unknown")

        echo "${node_info} ${node_model}" >> "${removable_file}"
        log INFO "Node LNN ${node} - Serial: $(echo ${node_info} | awk '{print $2}') - Model: ${node_model}"

        node_count=$(expr ${node_count} + 1)
    done < "${temp_nodes_file}"

    rm -f "${temp_nodes_file}"

    if [ ${node_count} -eq 0 ]; then
        log ERROR "No valid nodes to remove"
        return 1
    fi
    
    log INFO "Total nodes to remove: ${node_count}"
    cat "${removable_file}" | tee -a "${logfile}"

    # User confirmation (skip if --force is set)
    if [ "${FORCE}" = false ]; then
        echo ""
        read -p "Do you want to proceed with removing ${node_count} nodes? (y/n): " user_ack
        if [ "${user_ack}" != "y" ]; then
            log INFO "User cancelled operation"
            return 0
        fi
    else
        log INFO "Force mode enabled - skipping user confirmation"
    fi

    log INFO "Proceeding with node removal..."

    removed_count=0
    sleep_long="${SLEEP_LONG:-${DEFAULT_SLEEP_LONG}}"
    sleep_short="${SLEEP_SHORT:-${DEFAULT_SLEEP_SHORT}}"

    # Process each node
    while IFS= read -r line; do
        lnn=$(echo "${line}" | awk '{print $1}')
        serial=$(echo "${line}" | awk '{print $2}')

        log INFO "Smartfailing node LNN: ${lnn} Serial: ${serial}"

        # Execute smartfail
        if ! log_exec isi devices node smartfail --node-lnn=${lnn} --force; then
            log ERROR "Failed to smartfail node ${lnn}"
            continue
        fi

        # Check if the smartfailing has completed
        # Wait for node to appear in isi devices node list (v0.70 procedure)
        # If not present, wait for 900 seconds and check again
        log INFO "Waiting for node ${lnn} to appear in node list..."
        wait_check="${DEFAULT_WAIT_CHECK:-900}"

        while ! isi devices node list --no-header --no-footer | grep -q "${serial}"; do
            mydatecheck=$(date)
            log INFO "Timestamp status-check: ${mydatecheck}"
            sleep "${wait_check}"
        done

        log INFO "Node ${lnn} has appeared in node list"

        # Get job report
        job_id=$(isi job reports list 2>/dev/null | grep -i "FlexProtect" | grep -i "Succeeded" | tail -1 | awk '{print $2}' || echo "")
        if [ -n "${job_id}" ]; then
            duration=$(isi job reports view "${job_id}" 2>/dev/null | grep -i "elapsed" | head -1 | awk '{print $5}' | sed 's/[()]//g' || echo "unknown")
            log INFO "Job ID: ${job_id} Duration: ${duration}"
        fi

        removed_count=$(expr ${removed_count} + 1)
        log INFO "Removed: ${removed_count}/${node_count}"

        # Grace period
        log INFO "Waiting ${sleep_short}s grace period..."
        sleep "${sleep_short}"

    done < "${removable_file}"
    
    log INFO "Node removal completed: ${removed_count}/${node_count}"
    return 0
}

################################################################################
# Node Addition Functions
################################################################################

add_nodes() {
    input="$1"
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Ensure LOG_DIR is set (use default if not)
    LOG_DIR="${LOG_DIR:-${DEFAULT_LOG_DIR}}"
    
    logfile="${LOG_DIR}/log-nodes-join_${timestamp}.txt"
    serials_file=$(echo "${input}" | sed 's/--nodes-add=//')

    log INFO "Starting node addition process"
    
    # Clean up previous log
    rm -f "${logfile}"
    
    # Validate file exists
    if [ ! -f "${serials_file}" ]; then
        log ERROR "Serials file not found: ${serials_file}"
        return 1
    fi
    
    log INFO "Reading serials from: ${serials_file}"
    
    # Get list of joinable nodes
    log INFO "Checking for joinable nodes..."
    isi devices node list --no-header --no-footer | awk '{print $1}' > "${LOG_DIR}/mgmt-joinable-nodes_${timestamp}.txt"

    # Validate serials
    not_found_file="${LOG_DIR}/mgmt-nodes-not-found_${timestamp}.log"
    rm -f "${not_found_file}"

    valid_count=0
    total_count=0

    while IFS= read -r serial; do
        serial=$(echo "${serial}" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        [ -z "${serial}" ] && continue

        total_count=$(expr ${total_count} + 1)

        if ! validate_serial "${serial}"; then
            echo "${serial}" >> "${not_found_file}"
            continue
        fi

        if ! grep -q "${serial}" "${LOG_DIR}/mgmt-joinable-nodes_${timestamp}.txt"; then
            log WARN "Serial ${serial} not found in joinable nodes"
            echo "${serial}" >> "${not_found_file}"
            continue
        fi

        valid_count=$(expr ${valid_count} + 1)
    done < "${serials_file}"

    if [ -f "${not_found_file}" ]; then
        log ERROR "Following serials were not found:"
        cat "${not_found_file}" | while read line; do
            log ERROR "  ${line}"
        done
        log ERROR "Exiting - no changes made"
        return 1
    fi

    if [ ${valid_count} -eq 0 ]; then
        log ERROR "No valid serials to add"
        return 1
    fi

    log INFO "Valid serials to add: ${valid_count}/${total_count}"

    # Display the serials to be added with details
    echo ""
    echo "Serials to be added:"
    while IFS= read -r serial; do
        serial=$(echo "${serial}" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        [ -z "${serial}" ] && continue
        if validate_serial "${serial}"; then
            if grep -q "${serial}" "${LOG_DIR}/mgmt-joinable-nodes_${timestamp}.txt"; then
                node_details=$(isi devices node list | egrep "${serial}")
                echo "${node_details}"
            fi
        fi
    done < "${serials_file}"
    echo ""

    # User confirmation (skip if --force is set)
    if [ "${FORCE}" = false ]; then
        read -p "Do you want to proceed with adding ${valid_count} nodes? (y/n): " user_ack
        if [ "${user_ack}" != "y" ]; then
            log INFO "User cancelled operation"
            return 0
        fi
    else
        log INFO "Force mode enabled - skipping user confirmation"
    fi

    log INFO "Proceeding with node addition..."

    added_count=0
    sleep_long="${SLEEP_LONG:-${DEFAULT_SLEEP_LONG}}"
    sleep_short="${SLEEP_SHORT:-${DEFAULT_SLEEP_SHORT}}"

    # Check for nodes in error/working state
    log INFO "Checking for nodes in ERROR or WORKING state..."
    join_state_output=$(isi devices node list --verbose --no-header --no-footer 2>/dev/null)

    if echo "${join_state_output}" | grep -qi "error"; then
        log ERROR "Found node in ERROR state - operator review required"
        return 1
    fi

    if echo "${join_state_output}" | grep -qi "work"; then
        log WARN "Found node in WORKING state - waiting ${sleep_long}s..."
        sleep "${sleep_long}"
    fi

    # Wait for a five minute grace period prior to proceeding to join a node (v0.70 procedure)
    log INFO "Waiting for 5 minutes grace period prior to proceeding to join a node..."
    sleep "${sleep_short}"

    # Add each node
    while IFS= read -r serial; do
        serial=$(echo "${serial}" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        [ -z "${serial}" ] && continue

        log INFO "Adding node with serial: ${serial}"

        # Add node
        if ! log_exec isi devices node add --serial-number="${serial}" --force; then
            log ERROR "Failed to add node ${serial}"
            continue
        fi

        # Check and verify that the node has been successfully added to the cluster
        # Wait for node to appear in isi_nodes output (v0.70 procedure)
        # If not present, wait for 900 seconds and check again
        log INFO "Waiting for node ${serial} to appear in cluster..."
        wait_check="${DEFAULT_WAIT_CHECK:-900}"

        while ! isi_nodes %{id} %{lnn} %{name} %{serialno} 2>/dev/null | grep -qi "${serial}"; do
            mydatecheck=$(date)
            log INFO "Timestamp status-check: ${mydatecheck}"
            sleep "${wait_check}"
        done

        log INFO "Node ${serial} has joined the cluster"

        # Get node details
        node_details=$(isi_nodes %{id} %{lnn} %{name} %{serialno} 2>/dev/null | grep -i "${serial}" || echo "")
        log INFO "Node details: ${node_details}"

        # Additional health checks if --healthcheck is enabled
        if [ "${HEALTHCHECK}" = true ]; then
            log INFO "Running additional health checks..."

            # Get LNN of the added node
            node_lnn=$(isi_nodes %{serialno} %{lnn} 2>/dev/null | egrep -i "${serial}" | awk '{print $2}')
            log INFO "Node LNN: ${node_lnn}"

            # Check 1: Battery state
            log INFO "Checking battery state..."
            check_id=$(isi healthcheck run battery_test_status -v 2>/dev/null | awk '{print $5}')
            log INFO "Assessing: ${check_id}"
            sleep 603
            battery_result=$(isi healthcheck view "${check_id}" 2>/dev/null | egrep "Result:" | awk '{print $2}')
            log INFO "Battery test result: ${battery_result}"

            if [ "${battery_result}" != "Pass" ]; then
                log ERROR "Battery test failed: ${battery_result}"
                log ERROR "User intervention required before proceeding to next node"
                if [ "${FORCE}" = false ]; then
                    read -p "Battery test failed. Continue anyway? (y/n): " user_ack
                    if [ "${user_ack}" != "y" ]; then
                        log INFO "User cancelled operation due to battery test failure"
                        return 1
                    fi
                else
                    log ERROR "Battery test failed - stopping operation"
                    return 1
                fi
            else
                log INFO "Battery test passed"

                # Check 2: Readonly mode
                log INFO "Checking readonly mode..."
                readonly_mode=$(isi readonly view --node-lnn=${node_lnn} 2>/dev/null | egrep "Mode:" | awk '{print $2}')
                log INFO "Readonly mode: ${readonly_mode}"

                if [ "${readonly_mode}" = "Yes" ]; then
                    log ERROR "Node is in readonly mode"
                    log ERROR "User intervention required before proceeding to next node"
                    if [ "${FORCE}" = false ]; then
                        read -p "Node in readonly mode. Continue anyway? (y/n): " user_ack
                        if [ "${user_ack}" != "y" ]; then
                            log INFO "User cancelled operation due to readonly mode"
                            return 1
                        fi
                    else
                        log ERROR "Node in readonly mode - stopping operation"
                        return 1
                    fi
                else
                    log INFO "Node is not in readonly mode"
                fi
            fi
        fi

        added_count=$(expr ${added_count} + 1)
        log INFO "Added: ${added_count}/${valid_count}"

        # Grace period
        log INFO "Waiting ${sleep_short}s grace period..."
        sleep "${sleep_short}"

    done < "${serials_file}"
    
    log INFO "Node addition completed: ${added_count}/${valid_count}"
    return 0
}

################################################################################
# Node Carving Functions
################################################################################

carve_nodes() {
    input="$1"
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Ensure LOG_DIR is set (use default if not)
    LOG_DIR="${LOG_DIR:-${DEFAULT_LOG_DIR}}"
    
    logfile="${LOG_DIR}/log-nodes-carved_${timestamp}.txt"
    carvable_file="${LOG_DIR}/mgmt-nodes-carvable_${timestamp}.txt"

    log INFO "Starting node carving process"

    # Clean up previous files
    rm -f "${logfile}" "${carvable_file}"

    # Parse input
    nodes_input=$(echo "${input}" | sed 's/--nodepool-carve=//')
    log INFO "Input nodes: ${nodes_input}"
    
    # Validate input format
    if ! echo "${nodes_input}" | grep -qE '^[0-9,]+$'; then
        log ERROR "Invalid input format. Expected comma-separated LNNs."
        return 1
    fi
    
    node_count=0
    source_pool=""
    source_pool_count=0
    min_pool_nodes="${MIN_POOL_NODES:-${DEFAULT_MIN_POOL_NODES}}"
    min_carve_nodes="${MIN_CARVE_NODES:-${DEFAULT_MIN_CARVE_NODES}}"

    # Use a temporary file to track valid nodes
    temp_nodes_file=$(mktemp)
    echo "${nodes_input}" | tr ',' '\n' > "${temp_nodes_file}"

    while IFS= read -r node; do
        node=$(echo "${node}" | tr -d ' ')
        [ -z "${node}" ] && continue

        if ! validate_lnn "${node}"; then
            continue
        fi

        log INFO "Processing node LNN: ${node}"

        # Get node information
        node_info=$(isi_nodes %{lnn} %{serialno} 2>/dev/null | grep -w "^${node}" || echo "")
        if [ -z "${node_info}" ]; then
            log ERROR "Node LNN ${node} not found in cluster"
            continue
        fi

        echo "${node_info}" >> "${carvable_file}"

        # Get node's current pool
        node_pool=$(isi status --node=${node} 2>/dev/null | grep -i "pools" | awk '{print $NF}' || echo "")
        log INFO "Node ${node} belongs to pool: ${node_pool}"

        # Initialize source pool on first iteration
        if [ -z "${source_pool}" ]; then
            source_pool="${node_pool}"
        fi

        # Check if all nodes are from same pool
        if [ "${node_pool}" != "${source_pool}" ]; then
            log ERROR "Nodes are from different pools: ${source_pool} vs ${node_pool}"
            log ERROR "All nodes must be from the same pool for carving"
            rm -f "${temp_nodes_file}"
            return 1
        fi

        node_count=$(expr ${node_count} + 1)
    done < "${temp_nodes_file}"

    rm -f "${temp_nodes_file}"

    if [ ${node_count} -eq 0 ]; then
        log ERROR "No valid nodes to carve"
        return 1
    fi
    
    # Get source pool node count
    source_pool_count=$(isi storagepool nodepools view "${source_pool}" 2>/dev/null | grep -i "Nodes:" | sed 's/Nodes://g' | sed 's/,//g' | wc -w | awk '{print $1}')
    log INFO "Source pool ${source_pool} has ${source_pool_count} nodes"

    # Calculate remaining nodes after carving
    remaining_nodes=$(expr ${source_pool_count} - ${node_count})
    log INFO "Nodes remaining after carving: ${remaining_nodes}"

    # Validate minimum nodes remaining
    if [ ${remaining_nodes} -lt ${min_pool_nodes} ]; then
        log ERROR "Cannot carve: would leave only ${remaining_nodes} nodes (minimum: ${min_pool_nodes})"
        return 1
    fi

    # Validate minimum nodes to carve
    if [ ${node_count} -lt ${min_carve_nodes} ]; then
        log ERROR "Cannot carve: only ${node_count} nodes (minimum: ${min_carve_nodes})"
        return 1
    fi

    # Check if pool is manually managed
    pool_mode=$(isi storagepool nodepools view "${source_pool}" 2>/dev/null | egrep "Manual:" | awk '{print $2}' || echo "No")
    log INFO "Pool ${source_pool} mode: ${pool_mode}"

    # Sanity check: cannot carve from manual pools
    if [ "${pool_mode}" = "Yes" ]; then
        log ERROR "Cannot carve from manually managed pool (Manual: Yes)"
        log ERROR "Nodes can only be carved from auto-managed pools"
        return 1
    fi
    
    log INFO "Nodes to carve: ${node_count}"
    cat "${carvable_file}" | tee -a "${logfile}"

    # User confirmation (skip if --force is set)
    if [ "${FORCE}" = false ]; then
        echo ""
        read -p "Do you want to proceed with carving ${node_count} nodes? (y/n): " user_ack
        if [ "${user_ack}" != "y" ]; then
            log INFO "User cancelled operation"
            return 0
        fi
    else
        log INFO "Force mode enabled - skipping user confirmation"
    fi
    
    log INFO "Proceeding with node carving..."

    # Use custom nodepool name if provided, otherwise generate random name
    if [ -n "${CARVE_NODEPOOL_NAME}" ]; then
        if ! validate_nodepool_name "${CARVE_NODEPOOL_NAME}"; then
            log ERROR "Invalid custom nodepool name"
            return 1
        fi
        carved_pool="${CARVE_NODEPOOL_NAME}"
        log INFO "Using custom nodepool name: ${carved_pool}"
    else
        random_suffix=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 3 | head -n 1)
        carved_pool="CARVEDPOOL-${random_suffix}"
        log INFO "Using auto-generated nodepool name: ${carved_pool}"
    fi

    # Check if manual override is needed (v0.70 procedure)
    # If manual override is already set, proceed without toggling
    # If not set, enable it temporarily for carving, then disable after
    manual_override=$(isi_gconfig smartpools.diskpools.manually_manage_system_flags 2>/dev/null || echo "false")

    if echo "${manual_override}" | grep -q "true"; then
        log INFO "Manual override is already set"
    else
        log INFO "Manual override is required to proceed"
        log INFO "Enabling manual nodepool configuration..."
        if ! log_exec isi_gconfig smartpools.diskpools.manually_manage_system_flags=true; then
            log ERROR "Failed to enable manual override"
            return 1
        fi
    fi

    # Create new nodepool
    log INFO "Creating nodepool: ${carved_pool}"
    log INFO "Current nodepools before carving:"
    isi storagepool nodepools list --verbose | tee -a "${logfile}"

    if ! log_exec isi storagepool nodepools create "${carved_pool}" --lnns="${nodes_input}" --verbose; then
        log ERROR "Failed to create nodepool"
        # Disable manual override if we enabled it
        if echo "${manual_override}" | grep -qv "true"; then
            log_exec isi_gconfig smartpools.diskpools.manually_manage_system_flags=false
        fi
        return 1
    fi

    log INFO "Nodepool created successfully"
    log INFO "Current nodepools after carving:"
    sleep 5
    isi storagepool nodepools list --verbose | tee -a "${logfile}"

    # Disable manual override if we enabled it (v0.70 procedure)
    # Only disable if it wasn't already set before we started
    if echo "${manual_override}" | grep -qv "true"; then
        log INFO "Disabling manual nodepool configuration..."
        log_exec isi_gconfig smartpools.diskpools.manually_manage_system_flags=false
    fi
    
    log INFO "Node carving completed"
    
    return 0
}

################################################################################
# Nodepool Removal Functions
################################################################################

remove_nodepool() {
    input="$1"
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Ensure LOG_DIR is set (use default if not)
    LOG_DIR="${LOG_DIR:-${DEFAULT_LOG_DIR}}"
    
    logfile="${LOG_DIR}/log-nodepool-removed_${timestamp}.txt"
    removable_file="${LOG_DIR}/mgmt-nodepool-removable_${timestamp}.txt"

    log INFO "Starting nodepool removal process"

    # Clean up previous files
    rm -f "${logfile}" "${removable_file}"

    # Parse input
    poolname=$(echo "${input}" | sed 's/--nodepool-remove=//')
    log INFO "Target nodepool: ${poolname}"

    # Validate pool exists
    if ! isi storagepool nodepools list | grep -q "${poolname}"; then
        log ERROR "Nodepool '${poolname}' not found"
        return 1
    fi

    # Get member nodes from the pool
    log INFO "Retrieving member nodes from nodepool..."
    nodes_output=$(isi storagepool nodepool view "${poolname}" 2>/dev/null | awk -F': ' '/^ *Nodes:/ {print $2}')

    if [ -z "${nodes_output}" ]; then
        log ERROR "No nodes found in nodepool '${poolname}'"
        return 1
    fi

    log INFO "Member nodes: ${nodes_output}"

    # Parse and validate each LNN
    node_count=0

    # Use a temporary file to track valid nodes
    temp_nodes_file=$(mktemp)
    echo "${nodes_output}" | tr ',' '\n' > "${temp_nodes_file}"

    while IFS= read -r node; do
        node=$(echo "${node}" | tr -d ' ')
        [ -z "${node}" ] && continue

        if ! validate_lnn "${node}"; then
            continue
        fi

        log INFO "Processing node LNN: ${node}"

        # Get node information
        node_info=$(isi_nodes %{lnn} %{serialno} 2>/dev/null | grep -w "^${node}" || echo "")
        if [ -z "${node_info}" ]; then
            log ERROR "Node LNN ${node} not found in cluster"
            continue
        fi

        # Get node model
        node_model=$(isi_for_array -n${node} "isi_hw_status | egrep 'Product:'" 2>/dev/null | awk '{print $3}' || echo "unknown")

        echo "${node_info} ${node_model}" >> "${removable_file}"
        log INFO "Node LNN ${node} - Serial: $(echo ${node_info} | awk '{print $2}') - Model: ${node_model}"

        node_count=$(expr ${node_count} + 1)
    done < "${temp_nodes_file}"

    rm -f "${temp_nodes_file}"

    if [ ${node_count} -eq 0 ]; then
        log ERROR "No valid nodes to remove"
        return 1
    fi

    if [ ${node_count} -lt 2 ]; then
        log ERROR "Nodepool must have at least 2 nodes for removal (found: ${node_count})"
        return 1
    fi

    log INFO "Total nodes to remove: ${node_count}"
    cat "${removable_file}" | tee -a "${logfile}"

    # User confirmation (skip if --force is set)
    if [ "${FORCE}" = false ]; then
        echo ""
        read -p "Do you want to proceed with removing ${node_count} nodes from nodepool '${poolname}'? (y/n): " user_ack
        if [ "${user_ack}" != "y" ]; then
            log INFO "User cancelled operation"
            return 0
        fi
    else
        log INFO "Force mode enabled - skipping user confirmation"
    fi

    log INFO "Proceeding with nodepool removal..."

    removed_count=0
    sleep_long="${SLEEP_LONG:-${DEFAULT_SLEEP_LONG}}"
    sleep_short="${SLEEP_SHORT:-${DEFAULT_SLEEP_SHORT}}"

    # Sort nodes in reverse numerical order (highest to lowest)
    sorted_nodes=$(cat "${removable_file}" | awk '{print $1}' | sort -rn)

    # Create arrays for processing
    temp_sorted_file=$(mktemp)
    echo "${sorted_nodes}" > "${temp_sorted_file}"

    total_nodes=$(wc -l < "${temp_sorted_file}")
    current_node=0

    while IFS= read -r lnn; do
        current_node=$(expr ${current_node} + 1)
        remaining_nodes=$(expr ${total_nodes} - ${current_node})

        # Get serial for this node
        serial=$(cat "${removable_file}" | grep "^${lnn}" | awk '{print $2}')

        log INFO "Processing node ${current_node}/${total_nodes}: LNN ${lnn} Serial: ${serial}"

        # Check if this is one of the last two nodes (when 2 or fewer nodes remain)
        if [ ${remaining_nodes} -le 1 ]; then
            # Get the next node for simultaneous smartfail
            next_lnn=$(tail -n +$(expr ${current_node} + 1) "${temp_sorted_file}" | head -n 1)
            next_serial=$(cat "${removable_file}" | grep "^${next_lnn}" | awk '{print $2}')

            log INFO "Smartfailing last two nodes simultaneously: ${lnn} and ${next_lnn}"

            # Smartfail both nodes simultaneously (execute separately for proper logging)
            log INFO "Smartfailing node LNN: ${lnn} Serial: ${serial}"
            if ! log_exec isi devices node smartfail --node-lnn=${lnn} --force; then
                log ERROR "Failed to smartfail node ${lnn}"
                rm -f "${temp_sorted_file}"
                return 1
            fi

            log INFO "Smartfailing node LNN: ${next_lnn} Serial: ${next_serial}"
            if ! log_exec isi devices node smartfail --node-lnn=${next_lnn} --force; then
                log ERROR "Failed to smartfail node ${next_lnn}"
                rm -f "${temp_sorted_file}"
                return 1
            fi

            # Check if the smartfailing has completed for both nodes
            # Wait for both nodes to appear in isi devices node list (v0.70 procedure)
            # If not present, wait for 900 seconds and check again
            log INFO "Waiting for nodes ${lnn} and ${next_lnn} to appear in node list..."
            wait_check="${DEFAULT_WAIT_CHECK:-900}"

            while ! isi devices node list --no-header --no-footer | grep -q "${serial}" || \
                  ! isi devices node list --no-header --no-footer | grep -q "${next_serial}"; do
                mydatecheck=$(date)
                log INFO "Timestamp status-check: ${mydatecheck}"
                sleep "${wait_check}"
            done

            log INFO "Nodes ${lnn} and ${next_lnn} have appeared in node list"

            removed_count=$(expr ${removed_count} + 2)
            log INFO "Removed: ${removed_count}/${node_count}"

            # Skip the next node since we already processed it
            current_node=$(expr ${current_node} + 1)
            break
        else
            # Smartfail single node
            log INFO "Smartfailing node LNN: ${lnn} Serial: ${serial}"

            if ! log_exec isi devices node smartfail --node-lnn=${lnn} --force; then
                log ERROR "Failed to smartfail node ${lnn}"
                continue
            fi

            # Check if the smartfailing has completed
            # Wait for node to appear in isi devices node list (v0.70 procedure)
            # If not present, wait for 900 seconds and check again
            log INFO "Waiting for node ${lnn} to appear in node list..."
            wait_check="${DEFAULT_WAIT_CHECK:-900}"

            while ! isi devices node list --no-header --no-footer | grep -q "${serial}"; do
                mydatecheck=$(date)
                log INFO "Timestamp status-check: ${mydatecheck}"
                sleep "${wait_check}"
            done

            log INFO "Node ${lnn} has appeared in node list"

            # Get job report
            job_id=$(isi job reports list 2>/dev/null | grep -i "FlexProtect" | grep -i "Succeeded" | tail -1 | awk '{print $2}' || echo "")
            if [ -n "${job_id}" ]; then
                duration=$(isi job reports view "${job_id}" 2>/dev/null | grep -i "elapsed" | head -1 | awk '{print $5}' | sed 's/[()]//g' || echo "unknown")
                log INFO "Job ID: ${job_id} Duration: ${duration}"
            fi

            removed_count=$(expr ${removed_count} + 1)
            log INFO "Removed: ${removed_count}/${node_count}"

            # Grace period
            log INFO "Waiting ${sleep_short}s grace period..."
            sleep "${sleep_short}"
        fi
    done < "${temp_sorted_file}"

    rm -f "${temp_sorted_file}"

    log INFO "Nodepool removal completed: ${removed_count}/${node_count}"
    log INFO "The following nodes were removed"
    log isi devices nodes list
    return 0
}

################################################################################
# Node Neighborhood Functions
################################################################################

list_neighborhoods() {
    log INFO "Listing node neighborhoods"
    
    # Use Python to get neighborhood information (obfuscated)
    python3 -c "import base64; exec(base64.b64decode('aW1wb3J0IGlzaS5zbWFydHBvb2xzLmRpc2twb29scyBhcyBzcGRwCgp0cnk6CiAgICBkcGNmZyA9IHNwZHAub3Blbl9jb25maWcoKQogICAgZGlza3Bvb2xfZGIgPSBkcGNmZy5fZ2V0X2RiKCkKICAgIG5laWdoYm9yaG9vZHMgPSBkcGNmZy5wcm92aXNpb25lci5jbHVzdGVyLm5laWdoYm9yaG9vZHMKICAgIHByaW50KGYiRm91bmQge2xlbihuZWlnaGJvcmhvb2RzKX0gbmVpZ2hib3Job29kczoiKQogICAgcHJpbnQoIk5laWdoYm9yaG9vZCBkZXZpY2UgSURzOiIpCiAgICBmb3IgbmVpZ2hib3Job29kIGluIG5laWdoYm9yaG9vZHM6CiAgICAgICAgcHJpbnQoZiIgIHtuZWlnaGJvcmhvb2QuY29udGVudHN9IikKZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgcHJpbnQoZiJFcnJvcjoge2V9IikK'))" 2>&1
    
    echo ""
    log INFO "Node information:"
    isi_nodes DEVICEID: %{devid} LNN: %{lnn} SERIAL: %{serialno}
    
    echo ""
    log INFO "Storage pool information:"
    isi storagepool list
    
    return 0
}

################################################################################
# Main Function
################################################################################

main() {
    operation=""

    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --nodes-remove=*)
                if [ -n "${operation}" ]; then
                    log ERROR "Only one operation can be specified at a time"
                    usage
                    exit 1
                fi
                operation="remove"
                REMOVE_NODES_LNN="$1"
                ;;

            --nodes-add=*)
                if [ -n "${operation}" ]; then
                    log ERROR "Only one operation can be specified at a time"
                    usage
                    exit 1
                fi
                operation="add"
                ADD_NODES_SERIALS="$1"
                ;;

            --nodepool-carve=*)
                if [ -n "${operation}" ]; then
                    log ERROR "Only one operation can be specified at a time"
                    usage
                    exit 1
                fi
                operation="carve"
                CARVE_NODES_LNN="$1"
                ;;

            --nodepool-name=*)
                CARVE_NODEPOOL_NAME="${1#*=}"
                ;;

            --force)
                FORCE=true
                ;;

            --verbose)
                VERBOSE=true
                ;;

            --healthcheck)
                HEALTHCHECK=true
                ;;

            --nodepool-list)
                if [ -n "${operation}" ]; then
                    log ERROR "Only one operation can be specified at a time"
                    usage
                    exit 1
                fi
                operation="list"
                ;;

            --nodepool-remove=*)
                if [ -n "${operation}" ]; then
                    log ERROR "Only one operation can be specified at a time"
                    usage
                    exit 1
                fi
                operation="remove_nodepool"
                REMOVE_NODEPOOL="$1"
                ;;

            --sleep-short=*)
                SLEEP_SHORT="${1#*=}"
                log INFO "Short sleep duration: ${SLEEP_SHORT}s"
                ;;

            --sleep-long=*)
                SLEEP_LONG="${1#*=}"
                log INFO "Long sleep duration: ${SLEEP_LONG}s"
                ;;

            --help|-h)
                usage
                exit 0
                ;;

            *)
                log ERROR "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    # Initialize logging
    init_logging

    # Acquire lock
    acquire_lock

    # Display banner
    log INFO "=== PowerScale Storage Management Script v${SCRIPT_VERSION} ==="
    log INFO "Script path: ${SCRIPT_PATH}"

    # Run pre-flight checks (skip for list operation)
    if [ "${operation}" != "list" ]; then
        if ! preflight_check; then
            log ERROR "Pre-flight checks failed"
            exit 1
        fi
    fi

    # Execute operation
    case "${operation}" in
        remove)
            if [ -z "${REMOVE_NODES_LNN}" ]; then
                log ERROR "No nodes specified for removal"
                usage
                exit 1
            fi
            remove_nodes "${REMOVE_NODES_LNN}"
            ;;

        add)
            if [ -z "${ADD_NODES_SERIALS}" ]; then
                log ERROR "No serials file specified for addition"
                usage
                exit 1
            fi
            add_nodes "${ADD_NODES_SERIALS}"
            ;;

        carve)
            if [ -z "${CARVE_NODES_LNN}" ]; then
                log ERROR "No nodes specified for carving"
                usage
                exit 1
            fi
            carve_nodes "${CARVE_NODES_LNN}"
            ;;

        list)
            list_neighborhoods
            ;;

        remove_nodepool)
            if [ -z "${REMOVE_NODEPOOL}" ]; then
                log ERROR "No nodepool specified for removal"
                usage
                exit 1
            fi
            remove_nodepool "${REMOVE_NODEPOOL}"
            ;;

        *)
            log ERROR "No operation specified"
            usage
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
