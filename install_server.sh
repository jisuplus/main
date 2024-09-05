#!/bin/bash
set -euo pipefail

function display_usage() {
  cat <<EOF
Usage: install_server.sh [--hostname <hostname>] [--api-port <port>] [--keys-port <port>]

  --hostname   The hostname to be used to access the management API and access keys
  --api-port   The port number for the management API
  --keys-port  The port number for the access keys
EOF
}

readonly SENTRY_LOG_FILE=${SENTRY_LOG_FILE:-}
FULL_LOG="$(mktemp -t speed_logXXX)"
LAST_ERROR="$(mktemp -t speed_last_errorXXX)"
readonly FULL_LOG LAST_ERROR

function log_command() {
  "$@" > >(tee -a "${FULL_LOG}") 2> >(tee -a "${FULL_LOG}" > "${LAST_ERROR}")
}

function log_error() {
  local -r ERROR_TEXT="\033[0;31m"  # red
  local -r NO_COLOR="\033[0m"
  echo -e "${ERROR_TEXT}$1${NO_COLOR}"
  echo "$1" >> "${FULL_LOG}"
}

function log_start_step() {
  log_for_sentry "$@"
  local -r str="> $*"
  local -ir lineLength=47
  echo -n "${str}"
  local -ir numDots=$(( lineLength - ${#str} - 1 ))
  if (( numDots > 0 )); then
    echo -n " "
    for _ in $(seq 1 "${numDots}"); do echo -n .; done
  fi
  echo -n " "
}

function run_step() {
  local -r msg="$1"
  log_start_step "${msg}"
  shift 1
  if log_command "$@"; then
    echo "OK"
  else
    return
  fi
}

function confirm() {
  echo -n "> $1 [Y/n] "
  local RESPONSE
  read -r RESPONSE
  RESPONSE=$(echo "${RESPONSE}" | tr '[:upper:]' '[:lower:]') || return
  [[ -z "${RESPONSE}" || "${RESPONSE}" == "y" || "${RESPONSE}" == "yes" ]]
}

function command_exists {
  command -v "$@" &> /dev/null
}

function log_for_sentry() {
  if [[ -n "${SENTRY_LOG_FILE}" ]]; then
    echo "[$(date "+%Y-%m-%d@%H:%M:%S")] install_server.sh" "$@" >> "${SENTRY_LOG_FILE}"
  fi
  echo "$@" >> "${FULL_LOG}"
}

function verify_docker_installed() {
  if command_exists docker; then
    return 0
  fi
  log_error "NOT INSTALLED"
  if ! confirm "Would you like to install Docker? This will run 'curl https://get.docker.com/ | sh'."; then
    exit 0
  fi
  if ! run_step "Installing Docker" install_docker; then
    log_error "Docker installation failed, please visit https://docs.docker.com/install for instructions."
    exit 1
  fi
  log_start_step "Verifying Docker installation"
  command_exists docker
}

function verify_docker_running() {
  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker info 2>&1 >/dev/null)"
  local -ir RET=$?
  if (( RET == 0 )); then
    return 0
  elif [[ "${STDERR_OUTPUT}" == *"Is the docker daemon running"* ]]; then
    start_docker
    return
  fi
  return "${RET}"
}

function fetch() {
  curl --silent --show-error --fail "$@"
}

function install_docker() {
  (
    umask 0022
    fetch https://get.docker.com/ | sh
  ) >&2
}

function start_docker() {
  systemctl enable --now docker.service >&2
}

function docker_container_exists() {
  docker ps | grep --quiet "$1"
}

function remove_shadowbox_container() {
  remove_docker_container "${CONTAINER_NAME}"
}

function remove_watchtower_container() {
  remove_docker_container watchtower
}

function remove_docker_container() {
  docker rm -f "$1" >&2
}

function handle_docker_container_conflict() {
  local -r CONTAINER_NAME="$1"
  local -r EXIT_ON_NEGATIVE_USER_RESPONSE="$2"
  local PROMPT="The container name \"${CONTAINER_NAME}\" is already in use by another container. This may happen when running this script multiple times."
  if [[ "${EXIT_ON_NEGATIVE_USER_RESPONSE}" == 'true' ]]; then
    PROMPT="${PROMPT} We will attempt to remove the existing container and restart it. Would you like to proceed?"
  else
    PROMPT="${PROMPT} Would you like to replace this container? If you answer no, we will proceed with the remainder of the installation."
  fi
  if ! confirm "${PROMPT}"; then
    if ${EXIT_ON_NEGATIVE_USER_RESPONSE}; then
      exit 0
    fi
    return 0
  fi
  if run_step "Removing ${CONTAINER_NAME} container" "remove_${CONTAINER_NAME}_container" ; then
    log_start_step "Restarting ${CONTAINER_NAME}"
    "start_${CONTAINER_NAME}"
    return $?
  fi
  return 1
}

function finish {
  local -ir EXIT_CODE=$?
  if (( EXIT_CODE != 0 )); then
    if [[ -s "${LAST_ERROR}" ]]; then
      log_error "\nLast error: $(< "${LAST_ERROR}")" >&2
    fi
    log_error "\nSorry! Something went wrong. If you can't figure this out, please copy and paste all this output into the Speed Manager screen, and send it to us, to see if we can help you." >&2
    log_error "Full log: ${FULL_LOG}" >&2
  else
    rm "${FULL_LOG}"
  fi
  rm "${LAST_ERROR}"
}

function get_random_port {
  local -i num=0 
  until (( 1024 <= num && num < 65536)); do
    num=$(( RANDOM + (RANDOM % 2) * 32768 ));
  done;
  echo "${num}";
}

function create_persisted_state_dir() {
  readonly STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  mkdir -p "${STATE_DIR}"
  chmod ug+rwx,g+s,o-rwx "${STATE_DIR}"
}

function safe_base64() {
  local url_safe
  url_safe="$(base64 -w 0 - | tr '/+' '_-')"
  echo -n "${url_safe%%=*}"  # Strip trailing = chars
}

function generate_secret_key() {
  SB_API_PREFIX="123456"  # Use fixed password
  readonly SB_API_PREFIX
}

function generate_certificate() {
  local -r CERTIFICATE_NAME="${STATE_DIR}/shadowbox-selfsigned"
  readonly SB_CERTIFICATE_FILE="${CERTIFICATE_NAME}.crt"
  readonly SB_PRIVATE_KEY_FILE="${CERTIFICATE_NAME}.key"
  declare -a openssl_req_flags=(
    -x509 -nodes -days 36500 -newkey rsa:4096
    -subj "/CN=${PUBLIC_HOSTNAME}"
    -keyout "${SB_PRIVATE_KEY_FILE}" -out "${SB_CERTIFICATE_FILE}"
  )
  openssl req "${openssl_req_flags[@]}" >&2
}

function generate_certificate_fingerprint() {
  local CERT_OPENSSL_FINGERPRINT
  CERT_OPENSSL_FINGERPRINT="$(openssl x509 -in "${SB_CERTIFICATE_FILE}" -noout -fingerprint)"
  local CERT_FINGERPRINT
  CERT_FINGERPRINT="$(echo "${CERT_OPENSSL_FINGERPRINT}" | cut -d '=' -f 2 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
  readonly CERT_FINGERPRINT
}

function start_shadowbox() {
  local -ar docker_shadowbox_flags=(
    --name "${CONTAINER_NAME}" --restart always --net host
    --label 'com.centurylinklabs.watchtower.enable=true'
    -v "${STATE_DIR}:${STATE_DIR}"
    -e "SB_STATE_DIR=${STATE_DIR}"
    -e "SB_API_PORT=${API_PORT}"
    -e "SB_API_PREFIX=${SB_API_PREFIX}"   # Use fixed password
    -e "SB_CERTIFICATE_FILE=${SB_CERTIFICATE_FILE}"
    -e "SB_PRIVATE_KEY_FILE=${SB_PRIVATE_KEY_FILE}"
    -e "SB_METRICS_URL=${SB_METRICS_URL:-}"
    -e "SB_DEFAULT_SERVER_NAME=${PUBLIC_HOSTNAME}"
  )
  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker run -d "${docker_shadowbox_flags[@]}" "${SB_IMAGE}" 2>&1)"
  if (( $? == 0 )); then
    return 0
  else
    log_error "Error while starting shadowbox container: ${STDERR_OUTPUT}"
    return 1
  fi
}
