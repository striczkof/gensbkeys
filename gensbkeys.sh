#!/bin/sh
# An over-engineered, mostly POSIX-compliant shell.

CONFIG="./gensbkeys.conf"

# Quickly check for dependancies
(
  which openssl
  which cert-to-efi-sig-list
  which sign-efi-sig-list
  which mkdir
  which cp
  which date
  which uname
  which uuidgen
) 1>/dev/null || exit 1

DATE_TIME_FILE="$(date "+%Y_%m_%d-%H_%M_%S_%Z")"
DATE_CERT_NAME="$(date "+%Y")"
HOSTNAME="$(uname -n)"

# shellcheck source=gensbkeys.conf
[ -e "${CONFIG}" ] && . "${CONFIG}"

# Declare default variables if still empty
[ -z "${GUID}" ] && GUID="$(uuidgen --random)" && RAND_GUID=y
[ -z "${SUBJ}" ] && SUBJ="/CN=${HOSTNAME} Secure Boot Certificates ${DATE_CERT_NAME}"
[ -z "${EXP_IN_DAYS}" ] && EXP_IN_DAYS=3650
[ -z "${RSA_SIZE}" ] && RSA_SIZE=4096
[ -z "${PK}" ] && PK="PK"
[ -z "${KEK}" ] && KEK="KEK"
[ -z "${db}" ] && db="db"
[ -z "${MOK}" ] && MOK="MOK"
[ -z "${PK_SUBJ}" ] && PK_SUBJ="Platform Key"
[ -z "${KEK_SUBJ}" ] && KEK_SUBJ="Key Exchange Key"
[ -z "${db_SUBJ}" ] && db_SUBJ="Signature Database"
[ -z "${MOK_SUBJ}" ] && MOK_SUBJ="Machine Owner Key"

[ -z "${WORK_DIR}" ] && WORK_DIR="sb-${DATE_TIME_FILE}"
[ -z "${PUB_CERT}" ] && PUB_CERT="auth"
[ -z "${PUB_OUT_DIR}" ] && PUB_OUT_DIR="out_pub"
[ -z "${PRIV_OUT_DIR}" ] && PRIV_OUT_DIR="out_priv"
[ -z "${PK_IN_DIR}" ] && PK_IN_DIR="./"
[ -z "${KEK_IN_DIR}" ] && KEK_IN_DIR="./"
[ -z "${PK_PUB_OUT_DIR}" ] && PK_PUB_OUT_DIR="${PUB_OUT_DIR}"
[ -z "${PK_PRIV_OUT_DIR}" ] && PK_PRIV_OUT_DIR="${PRIV_OUT_DIR}"
[ -z "${KEK_PUB_OUT_DIR}" ] && KEK_PUB_OUT_DIR="${PUB_OUT_DIR}"
[ -z "${KEK_PRIV_OUT_DIR}" ] && KEK_PRIV_OUT_DIR="${PRIV_OUT_DIR}"
[ -z "${db_PUB_OUT_DIR}" ] && db_PUB_OUT_DIR="${PUB_OUT_DIR}"
[ -z "${db_PRIV_OUT_DIR}" ] && db_PRIV_OUT_DIR="${PRIV_OUT_DIR}"
[ -z "${MOK_PUB_OUT_DIR}" ] && MOK_PUB_OUT_DIR="${PUB_OUT_DIR}"
[ -z "${MOK_PRIV_OUT_DIR}" ] && MOK_PRIV_OUT_DIR="${PRIV_OUT_DIR}"

#[ -z "${LOG_FILE}" ] # Eh, don't log then
#[ -z "${DEL_CD}" ] # If set, delete working directory after completion


main() {
  print "maint test"

  # Create working directory
  echo "$WORK_DIR"
  mkdir "${WORK_DIR}" >/dev/null 2>&1 || WORK_DIR="$(mktemp -d)}" && [ -w "$WORK_DIR" ] || err "Failed to create working directory"
  [ -w "${WORK_DIR}" ] || err "Working directory is not writable"
  cd "$WORK_DIR" || err "Failed to cd into working directory"
  gen_PK
  gen_KEK
  gen_db
  gen_MOK
  WORK_DIR=$(realpath "./")
  cd || err "Failed to cd out of working directory"
  [ -z "${DEL_CD}" ] || rm -rf "${WORK_DIR}" && print "Deleted working directory ${WORK_DIR}"
}

gen_PK() {
  print "Generating Platform Key"
  openssl req -newkey "rsa:${RSA_SIZE}" -nodes -keyout ${PK}.key -new -x509 -sha256 -days ${EXP_IN_DAYS} -subj "${SUBJ} ${PK_SUBJ}" -out ${PK}.crt
  openssl x509 -outform DER -in ${PK}.crt -out ${PK}.cer
  cert-to-efi-sig-list -g "${GUID}" ${PK}.crt ${PK}.esl
  sign-efi-sig-list -g "${GUID}" -k ${PK}.key -c ${PK}.crt ${PK} ${PK}.esl ${PK}.auth
  # Copy to out directories
  mkdir -p ${PK_PUB_OUT_DIR} || pub_fail=1
  [ -w "${PK_PUB_OUT_DIR}" ] || pub_fail=1
  mkdir -p ${PK_PRIV_OUT_DIR} || priv_fail=1
  [ -w "${PK_PRIV_OUT_DIR}" ] || priv_fail=1
  # Proceed to copy
  [ -n "${pub_fail}" ] && warn "Not copying ${PK}.${PUB_CERT}."
  [ -n "${priv_fail}" ] && warn "Not copying PK private key and cert."
  if [ -z "${pub_fail}" ]
  then
    cp ${PK}.${PUB_CERT} "${PK_PUB_OUT_DIR}/" || warn "Failed to copy ${PK}.${PUB_CERT} to ${PK_PUB_OUT_DIR}"
    print "Copied PK public cert to ${PK_PUB_OUT_DIR}"
  fi
  if [ -z "${priv_fail}" ]
  then
    cp ${PK}.key "${PK_PRIV_OUT_DIR}/" || warn "Failed to copy ${PK}.key to ${PK_PRIV_OUT_DIR}"
    cp ${PK}.crt "${PK_PRIV_OUT_DIR}/" || warn "Failed to copy ${PK}.crt to ${PK_PRIV_OUT_DIR}"
    print "Copied PK private key and cert to ${PK_PRIV_OUT_DIR}"
  fi
  pub_fail=""
  priv_fail=""
}

gen_KEK() {
  if [ ! -f "${PK_IN_DIR}/${PK}.key" ] || [ ! -f "${PK_IN_DIR}/${PK}.crt" ]
  then
    warn "Signing Platform Key private key or cert not found in ${PK_IN_DIR}, can't generate Key Exchange Key."
    return 1
  fi
  # Trying to get the GUID if it's been generated already.
  if [ "$(realpath "./")" != "$(realpath "${PK_IN_DIR}")" ] && [ -n "$RAND_GUID" ]
  then
    if [ -f "${PK_IN_DIR}/GUID.txt" ]
    then
      GUID="$(cat "${PK_IN_DIR}/GUID.txt")"
    elif [ -f "${PK_IN_DIR}/UUID.txt" ]
    then
      GUID="$(cat "${PK_IN_DIR}/GUID.txt")"
    fi
  fi
  [ "$(realpath "./")" != "$(realpath "${PK_IN_DIR}")" ] && [ -n "$RAND_GUID" ] && warn "Other PK specified but using random GUID. They will not match!"
  print "Generating Key Exchange Key"
  openssl req -newkey "rsa:${RSA_SIZE}" -nodes -keyout ${KEK}.key -new -x509 -sha256 -days ${EXP_IN_DAYS} -subj "${SUBJ} ${KEK_SUBJ}" -out ${KEK}.crt
  openssl x509 -outform DER -in ${KEK}.crt -out ${KEK}.cer
  cert-to-efi-sig-list -g "${GUID}" ${KEK}.crt ${KEK}.esl
  sign-efi-sig-list -g "${GUID}" -k ${PK}.key -c ${PK}.crt ${KEK} ${KEK}.esl ${KEK}.auth
  # Copy to out directories
  mkdir -p ${KEK_PUB_OUT_DIR} || pub_fail=1
  [ -w "${KEK_PUB_OUT_DIR}" ] || pub_fail=1
  mkdir -p ${KEK_PRIV_OUT_DIR} || priv_fail=1
  [ -w "${KEK_PRIV_OUT_DIR}" ] || priv_fail=1
  # Proceed to copy
  [ -n "${pub_fail}" ] && warn "Not copying ${KEK}.${PUB_CERT}."
  [ -n "${priv_fail}" ] && warn "Not copying KEK private key and cert."
  if [ -z "${pub_fail}" ]
  then
    cp ${KEK}.${PUB_CERT} "${KEK_PUB_OUT_DIR}/" || warn "Failed to copy ${KEK}.${PUB_CERT} to ${KEK_PUB_OUT_DIR}"
    print "Copied KEK public cert to ${KEK_PUB_OUT_DIR}"
  fi
  if [ -z "${priv_fail}" ]
  then
    cp ${KEK}.key "${KEK_PRIV_OUT_DIR}/" || warn "Failed to copy ${KEK}.key to ${KEK_PRIV_OUT_DIR}"
    cp ${KEK}.crt "${KEK_PRIV_OUT_DIR}/" || warn "Failed to copy ${KEK}.crt to ${KEK_PRIV_OUT_DIR}"
    print "Copied KEK private key and cert to ${KEK_PRIV_OUT_DIR}"
  fi
  pub_fail=""
  priv_fail=""
}

gen_db() {
  if [ ! -f "${KEK_IN_DIR}/${KEK}.key" ] || [ ! -f "${KEK_IN_DIR}/${KEK}.crt" ]
  then
    warn "Signing Key Exchange Key private key or cert not found in ${KEK_IN_DIR}, can't generate Signature Database."
    return 1
  fi
  [ "$(realpath "./")" != "$(realpath "${KEK_IN_DIR}")" ] && [ -n "$RAND_GUID" ] && warn "Other KEK specified but using random GUID. They will not match!"
  print "Generating Signature Database"
  openssl req -newkey "rsa:${RSA_SIZE}" -nodes -keyout ${db}.key -new -x509 -sha256 -days ${EXP_IN_DAYS} -subj "${SUBJ} ${db_SUBJ}" -out ${db}.crt
  openssl x509 -outform DER -in ${db}.crt -out ${db}.cer
  cert-to-efi-sig-list -g "${GUID}" ${db}.crt ${db}.esl
  sign-efi-sig-list -g "${GUID}" -k ${KEK}.key -c ${KEK}.crt ${db} ${db}.esl ${db}.auth
  # Copy to out directories
  mkdir -p ${db_PUB_OUT_DIR} || pub_fail=1
  [ -w "${db_PUB_OUT_DIR}" ] || pub_fail=1
  mkdir -p ${db_PRIV_OUT_DIR} || priv_fail=1
  [ -w "${db_PRIV_OUT_DIR}" ] || priv_fail=1
  # Proceed to copy
  [ -n "${pub_fail}" ] && warn "Not copying ${db}.${PUB_CERT}."
  [ -n "${priv_fail}" ] && warn "Not copying db private key and cert."
  if [ -z "${pub_fail}" ]
  then
    cp ${db}.${PUB_CERT} "${db_PUB_OUT_DIR}/" || warn "Failed to copy ${db}.${PUB_CERT} to ${db_PUB_OUT_DIR}"
    print "Copied db public cert to ${db_PUB_OUT_DIR}"
  fi
  if [ -z "${priv_fail}" ]
  then
    cp ${db}.key "${db_PRIV_OUT_DIR}/" || warn "Failed to copy ${db}.key to ${db_PRIV_OUT_DIR}"
    cp ${db}.crt "${db_PRIV_OUT_DIR}/" || warn "Failed to copy ${db}.crt to ${db_PRIV_OUT_DIR}"
    print "Copied db private key and cert to ${db_PRIV_OUT_DIR}"
  fi
  pub_fail=""
  priv_fail=""
}

gen_MOK() {
  print "Generating Machine Owner Key"
  openssl req -newkey "rsa:${RSA_SIZE}" -nodes -keyout ${MOK}.key -new -x509 -sha256 -days ${EXP_IN_DAYS} -subj "${SUBJ} ${MOK_SUBJ}" -out ${MOK}.crt
  openssl x509 -outform DER -in ${MOK}.crt -out ${MOK}.cer
  # Copy to out directories
  mkdir -p ${MOK_PUB_OUT_DIR} || pub_fail=1
  [ -w "${MOK_PUB_OUT_DIR}" ] || pub_fail=1
  mkdir -p ${MOK_PRIV_OUT_DIR} || priv_fail=1
  [ -w "${MOK_PRIV_OUT_DIR}" ] || priv_fail=1
  # Proceed to copy
  [ -n "${pub_fail}" ] && warn "Not copying ${MOK}.cer."
  [ -n "${priv_fail}" ] && warn "Not copying MOK private key and cert."
  if [ -z "${pub_fail}" ]
  then
    cp ${MOK}.cer "${MOK_PUB_OUT_DIR}/" || warn "Failed to copy ${MOK}.cer to ${MOK_PUB_OUT_DIR}"
    print "Copied MOK public cert to ${MOK_PUB_OUT_DIR}"
  fi
  if [ -z "${priv_fail}" ]
  then
    cp ${MOK}.key "${MOK_PRIV_OUT_DIR}/" || warn "Failed to copy ${MOK}.key to ${MOK_PRIV_OUT_DIR}"
    cp ${MOK}.crt "${MOK_PRIV_OUT_DIR}/" || warn "Failed to copy ${MOK}.crt to ${MOK_PRIV_OUT_DIR}"
    print "Copied MOK private key and cert to ${MOK_PRIV_OUT_DIR}"
  fi
  pub_fail=""
  priv_fail=""
}

print() {
  if [ -z "${LOG_FILE}" ]
  then
    printf "%s\n" "$@"
  else
    printf "%s\n" "$@" 2>&1 | tee -a "${LOG_FILE}"
  fi
}

warn() {
  print "Warning: $1"
}

err() {
  print "Error: ${*}"
  exit 1
}

main "$@"
