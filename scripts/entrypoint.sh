#!/bin/bash
set -euo pipefail

# 环境默认值（必须提供本地管理员用户名/密码）
LDAP_BASE_DN="${LDAP_BASE_DN:-dc=example,dc=com}"
LDAP_LOCAL_ADMIN_USERNAME="${LDAP_LOCAL_ADMIN_USERNAME:-}"
LDAP_LOCAL_ADMIN_PASSWORD="${LDAP_LOCAL_ADMIN_PASSWORD:-}"
if [ -z "${LDAP_LOCAL_ADMIN_USERNAME}" ] || [ -z "${LDAP_LOCAL_ADMIN_PASSWORD}" ]; then
  echo "LDAP_LOCAL_ADMIN_USERNAME and LDAP_LOCAL_ADMIN_PASSWORD must be set" >&2
  exit 1
fi
LDAP_ROOT_DN="cn=${LDAP_LOCAL_ADMIN_USERNAME},${LDAP_BASE_DN}"
LDAP_SERVER_ID="${LDAP_SERVER_ID:-1}"
SLAPD_LOG_LEVEL="${SLAPD_LOG_LEVEL:-stats}"

LDAP_PROVIDER_URI="${LDAP_PROVIDER_URI:-ldap.example.com:389}"
LDAP_PROVIDER_BIND_DN="${LDAP_PROVIDER_BIND_DN:-uid=sync,cn=users,${LDAP_BASE_DN}}"
LDAP_PROVIDER_BIND_PW="${LDAP_PROVIDER_BIND_PW:-}"
LDAP_PROVIDER_SEARCHBASE="${LDAP_PROVIDER_SEARCHBASE:-${LDAP_BASE_DN}}"
LDAP_PROVIDER_SECURITY="${LDAP_PROVIDER_SECURITY:-none}" # 可选 ssl/starttls/none
LDAP_PROVIDER_TLS_REQCERT="${LDAP_PROVIDER_TLS_REQCERT:-never}" # 可选 never/demand
AUTO_FETCH_SCHEMA="${AUTO_FETCH_SCHEMA:-false}" # true/false
PROVIDER_MODE="none"

CERT_CA="${CERT_CA:-/etc/ssl/certs/ca-certificates.crt}"
CERT_CRT="${CERT_CRT:-/certs/ldap.crt}"
CERT_KEY="${CERT_KEY:-/certs/ldap.key}"
LDAP_CLIENT_CONF="/etc/ldap/ldap.conf"

if [ ! -f "${CERT_CA}" ]; then
  echo "WARN: CERT_CA not found at ${CERT_CA}, falling back to /etc/ssl/certs/ca-certificates.crt" >&2
  CERT_CA="/etc/ssl/certs/ca-certificates.crt"
fi
export CERT_CA CERT_CRT CERT_KEY

DB_DIR="/var/lib/ldap"
CONF_DIR="/etc/ldap"
SLAPD_CONF="/etc/ldap/slapd.conf"

# POSIX 补充（满足 QNAP/NAS 对 memberUid/gidNumber 的期望）
ENABLE_POSIX_AUGMENT="${ENABLE_POSIX_AUGMENT:-true}"
POSIX_AUGMENT_INTERVAL="${POSIX_AUGMENT_INTERVAL:-900}" # 秒

hash_pw() {
  slappasswd -s "${LDAP_LOCAL_ADMIN_PASSWORD}"
}

normalize_provider_uri() {
  local uri="$1" security="$2"
  if [[ "$uri" == *"://"* ]]; then
    echo "$uri"
    return
  fi
  case "${security,,}" in
    ssl) echo "ldaps://${uri}" ;;
    *) echo "ldap://${uri}" ;;
  esac
}

normalize_provider_security() {
  case "${LDAP_PROVIDER_SECURITY,,}" in
    ssl)
      PROVIDER_MODE="ssl"
      ;;
    starttls)
      PROVIDER_MODE="starttls"
      ;;
    none|"")
      PROVIDER_MODE="none"
      ;;
    *)
      echo "Invalid LDAP_PROVIDER_SECURITY=${LDAP_PROVIDER_SECURITY}, must be one of ssl/starttls/none" >&2
      exit 1
      ;;
  esac
}

render_conf() {
  local hashed
  hashed="$(hash_pw)"
  local provider_uri normalized
  provider_uri="$(normalize_provider_uri "${LDAP_PROVIDER_URI}" "${LDAP_PROVIDER_SECURITY}")"
  normalize_provider_security
  cat > "${SLAPD_CONF}" <<EOF
include         /etc/ldap/schema/core.schema
include         /etc/ldap/schema/cosine.schema
include         /etc/ldap/schema/inetorgperson.schema
include         /etc/ldap/schema/nis.schema
allow bind_v2
loglevel ${SLAPD_LOG_LEVEL}

pidfile         /run/slapd/slapd.pid
argsfile        /run/slapd/slapd.args

moduleload      syncprov
modulepath      /usr/lib/ldap
moduleload      back_mdb

serverID ${LDAP_SERVER_ID}

database mdb
maxsize 1073741824
suffix  "${LDAP_BASE_DN}"
directory ${DB_DIR}
rootdn  "${LDAP_ROOT_DN}"
rootpw  ${hashed}
index objectClass eq

overlay syncprov
syncprov-checkpoint 100 10
syncprov-sessionlog 100

syncrepl rid=${LDAP_SERVER_ID} \\
  provider=${provider_uri} \\
  type=refreshAndPersist \\
  bindmethod=simple \\
  binddn="${LDAP_PROVIDER_BIND_DN}" \\
  credentials="${LDAP_PROVIDER_BIND_PW}" \\
  searchbase="${LDAP_PROVIDER_SEARCHBASE}" \\
  schemachecking=off \\
  retry="5 5 300 +" \\
  timeout=1 \\
  starttls=$([ "${PROVIDER_MODE}" = "starttls" ] && echo "yes" || echo "no") \\
  tls_cacert=${CERT_CA} \\
  tls_reqcert=${LDAP_PROVIDER_TLS_REQCERT}
updateref ${provider_uri}
EOF

  # 追加 TLS 信任根（用于验证 Provider，也用于本地 LDAPS）
  if [ -f "${CERT_CA}" ]; then
    cat >> "${SLAPD_CONF}" <<EOF
TLSCACertificateFile ${CERT_CA}
EOF
  fi

  # 如有本地 LDAPS 证书/私钥则写入
  if [ -f "${CERT_CRT}" ] && [ -f "${CERT_KEY}" ]; then
    cat >> "${SLAPD_CONF}" <<EOF
TLSCertificateFile   ${CERT_CRT}
TLSCertificateKeyFile ${CERT_KEY}
EOF
  fi

  # 追加自定义 schema（如存在）
  shopt -s nullglob
  for s in /schema/custom/*.schema; do
    [ -f "$s" ] || continue
    echo "include         ${s}" >> "${SLAPD_CONF}"
  done
}

render_client_conf() {
  mkdir -p /etc/ldap
  cat > "${LDAP_CLIENT_CONF}" <<EOF
TLS_REQCERT ${LDAP_PROVIDER_TLS_REQCERT}
TLS_CACERT ${CERT_CA}
EOF
}

slapd_listeners() {
  local listeners="ldap:/// ldapi:///"
  if [ -f "${CERT_CRT}" ] && [ -f "${CERT_KEY}" ]; then
    listeners="${listeners} ldaps:///"
  fi
  echo "${listeners}"
}

fetch_provider_schema() {
  # 自动拉取并清理 Provider schema（仅保留自定义部分），失败忽略
  [ "${AUTO_FETCH_SCHEMA}" = "true" ] || return 0
  [ -n "${LDAP_PROVIDER_BIND_PW}" ] || return 0
  local provider_uri
  provider_uri="$(normalize_provider_uri "${LDAP_PROVIDER_URI}" "${LDAP_PROVIDER_SECURITY}")"
  /usr/bin/env python3 /usr/local/bin/ldap-syncctl.py fetch-schema \
    --uri "${provider_uri}" \
    --bind-dn "${LDAP_PROVIDER_BIND_DN}" \
    --bind-pw "${LDAP_PROVIDER_BIND_PW}" \
    --out "/schema/custom/provider.schema" \
    $( [ "${PROVIDER_MODE}" = "starttls" ] && echo "--starttls" ) \
    $( [ "${PROVIDER_MODE}" = "ssl" ] && echo "--ssl" ) \
    --tls-reqcert "${LDAP_PROVIDER_TLS_REQCERT}" || true
}

mkdir -p /run/slapd "${DB_DIR}"

# 导出本地默认值，便于辅助脚本使用（可被环境变量覆盖）
export LDAP_URI="${LDAP_URI:-ldap://localhost:389}"
export BIND_DN="${BIND_DN:-${LDAP_ROOT_DN}}"
export BIND_PW="${BIND_PW:-${LDAP_LOCAL_ADMIN_PASSWORD}}"
export LDAP_BASE_DN="${LDAP_BASE_DN}"

normalize_provider_security
fetch_provider_schema
render_conf
render_client_conf

# 启动前校验配置
if ! slaptest -u -f "${SLAPD_CONF}"; then
  echo "slaptest failed, exiting"
  exit 1
fi

start_posix_augment_loop() {
  [ "${ENABLE_POSIX_AUGMENT}" = "true" ] || return 0
  (
    # 等待 slapd 就绪以接受 ldapi 连接
    sleep 3
    while true; do
      LDAP_URI="ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi" \
        /usr/bin/env python3 /usr/local/bin/ldap-syncctl.py fix-posix-groups \
        --external \
        --base-dn "${LDAP_BASE_DN}" || true
      sleep "${POSIX_AUGMENT_INTERVAL}"
    done
  ) &
}

/usr/sbin/slapd -d "${SLAPD_LOG_LEVEL}" -h "$(slapd_listeners)" -f "${SLAPD_CONF}" &
SLAPD_PID=$!
start_posix_augment_loop
wait "${SLAPD_PID}"
