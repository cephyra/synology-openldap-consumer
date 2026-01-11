#!/usr/bin/env python3
"""
群晖 -> OpenLDAP consumer 辅助 CLI（默认使用 Provider 配置，本地命令会改用本地管理员）：
1) fetch-schema : 拉取并清洗 Provider schema，输出 provider.schema
2) list-users   : 列出用户
3) list-groups  : 列出组
4) resync-full  : 清空 contextCSN 触发全量同步
5) show-csn     : 查看当前 contextCSN

环境变量（主要是 Provider 配置，加上本地管理员凭据）：
- Provider：LDAP_PROVIDER_URI / LDAP_PROVIDER_BIND_DN / LDAP_PROVIDER_BIND_PW / LDAP_PROVIDER_SEARCHBASE / LDAP_PROVIDER_SECURITY(ssl|starttls|none) / LDAP_PROVIDER_TLS_REQCERT(never|demand)
- 本地：URI 固定 ldap://localhost:389；本地管理员 DN 由 LDAP_LOCAL_ADMIN_USERNAME + LDAP_BASE_DN 组成，密码为 LDAP_LOCAL_ADMIN_PASSWORD；默认不加密（starttls=no，tls_reqcert=never）
- BASE：LDAP_BASE_DN（必填，否则需通过参数提供）
fetch-schema 使用 Provider 配置，其他命令自动使用本地配置。支持 StartTLS 或 LDAPS（ldaps:// 默认不开启 StartTLS，可用 --ssl 或 --no-starttls 调整）。
"""
import os
import sys
import argparse
import ssl
import re
import shutil
from pathlib import Path
from ldap3 import Server, Connection, Tls, ALL, MODIFY_REPLACE, MODIFY_ADD

DEFAULT_BASE = os.getenv('LDAP_BASE_DN')
CA_CERT_PATH = os.getenv('CERT_CA', '/etc/ssl/certs/ca-certificates.crt')

def parse_line(line: str):
    m = re.match(r"\(\s*([0-9\.]+)\s+NAME\s+'?\(?([^)]*)\)?", line)
    oid = m.group(1) if m else ""
    names_raw = m.group(2) if m else ""
    names = [n.strip().strip("'") for n in re.split(r"\s+'?\s*", names_raw) if n.strip("'").strip()]
    return oid, names

def load_schema_oids_from_files(paths):
    oids = set()
    for p in paths:
        try:
            content = Path(p).read_text(encoding='utf-8', errors='ignore')
        except FileNotFoundError:
            continue
        # 逐行粗略扫描，收集 schema 定义开头的 OID
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("attributetype") or line.startswith("objectclass"):
                oid, _ = parse_line(line[line.find("("):]) if "(" in line else ("", [])
                if oid:
                    oids.add(oid)
    return oids

def mk_tls(tls_reqcert: str):
    validate = ssl.CERT_NONE if tls_reqcert == 'never' else ssl.CERT_REQUIRED
    ca_file = CA_CERT_PATH if CA_CERT_PATH and os.path.exists(CA_CERT_PATH) else None
    return Tls(validate=validate, ca_certs_file=ca_file)

def ldap_conn(uri, bind_dn, bind_pw, starttls=False, tls_reqcert="demand", force_ssl=False, external=False):
    # ldapi+EXTERNAL 快速路径：无需 TLS/凭证
    if external:
        srv = Server(uri, get_info=ALL)
        conn = Connection(
            srv,
            authentication="SASL",
            sasl_mechanism="EXTERNAL",
            sasl_credentials=(),
            auto_bind=True,
        )
        return conn

    use_ssl = uri.startswith("ldaps://") or force_ssl
    if use_ssl:
        starttls = False
    srv = Server(uri, get_info=ALL, tls=mk_tls(tls_reqcert), use_ssl=use_ssl)
    conn = Connection(srv, user=bind_dn, password=bind_pw, auto_bind=False)
    conn.open()
    if starttls:
        conn.start_tls()
    if not conn.bind():
        raise RuntimeError(f"Bind failed: {conn.last_error}")
    return conn

def collect_oids(conn):
    conn.search('cn=subschema', '(objectClass=*)', attributes=['attributeTypes', 'objectClasses'])
    if not conn.entries:
        return set()
    entry = conn.entries[0]
    attrs = entry.attributeTypes.values if 'attributeTypes' in entry else []
    objs = entry.objectClasses.values if 'objectClasses' in entry else []
    oids = set()
    for raw in list(attrs) + list(objs):
        oid, _ = parse_line(raw)
        if oid:
            oids.add(oid)
    return oids

def cmd_fetch_schema(args):
    # 预先加载已有 schema OID（扫描 /etc/ldap/schema 和 /schema/custom），避免重复
    schema_files = []
    for schema_dir in (Path("/etc/ldap/schema"), Path("/schema/custom")):
        if schema_dir.exists():
            for f in schema_dir.glob("*.schema"):
                schema_files.append(str(f))
    standard_oids = load_schema_oids_from_files(schema_files)

    # 拉取 Provider schema
    conn = ldap_conn(args.uri, args.bind_dn, args.bind_pw, args.starttls, args.tls_reqcert)
    conn.search('cn=subschema', '(objectClass=*)', attributes=['attributeTypes', 'objectClasses'])
    if not conn.entries:
        raise RuntimeError("No subschema returned")
    entry = conn.entries[0]
    attrs = entry.attributeTypes.values if 'attributeTypes' in entry else []
    objs = entry.objectClasses.values if 'objectClasses' in entry else []

    out_lines = []
    existing_oids = set(standard_oids)
    for raw in attrs:
        oid, _ = parse_line(raw)
        if oid and oid not in existing_oids:
            out_lines.append(f"attributetype {raw.strip()}")
            existing_oids.add(oid)
    for raw in objs:
        oid, _ = parse_line(raw)
        if oid and oid not in existing_oids:
            out_lines.append(f"objectclass {raw.strip()}")
            existing_oids.add(oid)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(out_lines) + "\n", encoding='utf-8')
    print(f"Wrote {len(out_lines)} definitions to {args.out}")

def cmd_list(args, filterstr, attrs):
    conn = ldap_conn(args.uri, args.bind_dn, args.bind_pw, args.starttls, args.tls_reqcert, external=args.external, force_ssl=args.ssl)
    conn.search(args.base_dn, filterstr, attributes=attrs)
    print(f"Found {len(conn.entries)} entries for {filterstr}")
    for e in conn.entries:
        print(e.entry_dn)

def cmd_fix_posix_groups(args):
    """
    为群晖同步的 groupOfNames/groupOfUniqueNames 提供 posixGroup 视图：
    - 如缺少 objectClass=posixGroup 则添加
    - 如缺少 gidNumber 则用 DN 的 crc32 生成稳定 gid
    - 从 member/uniqueMember 提取 uid RDN 生成 memberUid，缺少则补充
    """
    import zlib

    conn = ldap_conn(args.uri, args.bind_dn, args.bind_pw, args.starttls, args.tls_reqcert, external=args.external, force_ssl=args.ssl)
    conn.search(
        args.base_dn,
        '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))',
        attributes=['objectClass', 'member', 'uniqueMember', 'memberUid', 'gidNumber'],
    )
    added_classes = added_gid = added_uid = 0
    for entry in conn.entries:
        dn = entry.entry_dn
        mods = {}

        obj_classes = [oc.lower() for oc in entry.objectClass.values] if 'objectClass' in entry else []
        if 'posixgroup' not in obj_classes:
            mods['objectClass'] = [(MODIFY_ADD, ['posixGroup'])]
            added_classes += 1

        if 'gidNumber' not in entry.entry_attributes_as_dict or not entry.gidNumber.values:
            gid = args.gid_offset + (zlib.crc32(dn.encode()) % args.gid_mod)
            mods['gidNumber'] = [(MODIFY_ADD, [str(gid)])]
            added_gid += 1

        members = []
        if 'member' in entry:
            members.extend(entry.member.values)
        if 'uniqueMember' in entry:
            members.extend(entry.uniqueMember.values)
        existing_uids = set(entry.memberUid.values) if 'memberUid' in entry else set()
        new_uids = []
        for mdn in members:
            m = re.search(r'uid=([^,]+)', mdn, re.IGNORECASE)
            if not m:
                continue
            uid = m.group(1)
            if uid not in existing_uids and uid not in new_uids:
                new_uids.append(uid)
        if new_uids:
            mods['memberUid'] = [(MODIFY_ADD, new_uids)]
            added_uid += len(new_uids)

        if mods:
            if not conn.modify(dn, mods):
                print(f"Warn: modify {dn} failed: {conn.last_error}")

    print(f"posixGroup fix done: added_class={added_classes}, added_gid={added_gid}, added_memberUid={added_uid}")

def cmd_resync_full(args):
    """
    行为：优先本地清空 contextCSN；若失败则清空本地 DB，作为新节点强制全量同步。
    """
    def reset_db():
        db_dir = os.getenv('LDAP_DB_DIR', '/var/lib/ldap')
        if not os.path.isdir(db_dir):
            raise RuntimeError(f"DB dir not found: {db_dir}")
        for name in os.listdir(db_dir):
            path = os.path.join(db_dir, name)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        print(f"Local DB wiped at {db_dir}; restart/next cycle will trigger full sync.")

    try:
        conn = ldap_conn(args.uri, args.bind_dn, args.bind_pw, args.starttls, args.tls_reqcert, external=args.external, force_ssl=args.ssl)
        manage_dsa_it = ('2.16.840.1.113730.3.4.2', True, None)
        ok = conn.modify(args.base_dn, {'contextCSN': [(MODIFY_REPLACE, [])]}, controls=[manage_dsa_it])
        if ok:
            print("Cleared contextCSN; next syncrepl cycle will do full refresh.")
            return
        # 失败则回退到重置
        print(f"Failed to clear contextCSN via LDAP: {conn.last_error}. Resetting local DB...")
    except Exception as exc:
        print(f"Modify contextCSN failed ({exc}); resetting local DB...")
    reset_db()

def cmd_show_csn(args):
    conn = ldap_conn(args.uri, args.bind_dn, args.bind_pw, args.starttls, args.tls_reqcert, external=args.external, force_ssl=args.ssl)
    conn.search(args.base_dn, '(objectClass=*)', attributes=['contextCSN'])
    if not conn.entries:
        print("No contextCSN found")
    else:
        csn = conn.entries[0].contextCSN.values if 'contextCSN' in conn.entries[0] else []
        print("contextCSN:", csn)

def env_default(name):
    return os.getenv(name)

def normalize_bind_dn(val, base):
    if not val:
        return None
    if '=' in val or ',' in val:
        return val
    return f"cn={val},{base}" if base else val

def add_common_opts(p, use_local: bool):
    def normalize_uri(uri_val, security):
        if not uri_val:
            return uri_val
        if "://" in uri_val:
            return uri_val
        if security == 'ssl':
            return f"ldaps://{uri_val}"
        return f"ldap://{uri_val}"

    if use_local:
        # 本地：默认 ldapi+EXTERNAL，无需密码；允许手工改为 TCP+密码
        uri = env_default('LDAP_LOCAL_URI') or 'ldapi://%2Frun%2Fslapd%2Fldapi'
        bind_dn = None
        bind_pw = None
        starttls_env = False
        tls_reqcert_env = 'never'
        force_ssl_env = False
        external_env = True
    else:
        # Provider 配置
        security = (env_default('LDAP_PROVIDER_SECURITY') or 'none').lower()
        uri = normalize_uri(env_default('LDAP_PROVIDER_URI'), security)
        bind_dn = env_default('LDAP_PROVIDER_BIND_DN')
        bind_pw = env_default('LDAP_PROVIDER_BIND_PW')
        starttls_env = False
        tls_reqcert_env = env_default('LDAP_PROVIDER_TLS_REQCERT') or 'demand'
        external_env = False
        if security == 'ssl':
            force_ssl_env = True
            starttls_env = False
        elif security == 'starttls':
            force_ssl_env = False
            starttls_env = True
        elif security in ('none', ''):
            force_ssl_env = False
        else:
            raise RuntimeError("Invalid LDAP_PROVIDER_SECURITY, must be ssl/starttls/none")

    p.add_argument('--uri', default=uri)
    p.add_argument('--bind-dn', default=bind_dn)
    p.add_argument('--bind-pw', default=bind_pw)
    p.add_argument('--starttls', dest='starttls', action='store_true', default=starttls_env)
    p.add_argument('--no-starttls', dest='starttls', action='store_false')
    p.add_argument('--ssl', dest='ssl', action='store_true', default=force_ssl_env, help='Use ldaps (disables starttls)')
    p.add_argument('--tls-reqcert', choices=['never', 'demand'], default=tls_reqcert_env)
    p.add_argument('--external', dest='external', action='store_true', default=external_env, help='Use SASL EXTERNAL (ldapi:///, no password)')
    p.add_argument('--no-external', dest='external', action='store_false')
    p.add_argument('--base-dn', default=DEFAULT_BASE)

def require_params(args, require_base=False):
    missing = []
    if not args.uri:
        missing.append('LDAP_URI/--uri')
    if not args.external:
        if not args.bind_dn:
            missing.append('BIND_DN/--bind-dn')
        if not args.bind_pw:
            missing.append('BIND_PW/--bind-pw')
    if require_base and not args.base_dn:
        missing.append('LDAP_BASE_DN/--base-dn')
    if missing:
        raise RuntimeError(f"Missing required params: {', '.join(missing)}")

def main():
    ap = argparse.ArgumentParser(description="Synology consumer helper CLI")
    sub = ap.add_subparsers(dest='cmd', required=True)

    ap_fetch = sub.add_parser('fetch-schema', help='Fetch and clean provider schema')
    add_common_opts(ap_fetch, use_local=False)
    ap_fetch.add_argument('--out', default='/schema/custom/provider.schema')
    ap_fetch.set_defaults(func=cmd_fetch_schema)

    ap_users = sub.add_parser('list-users', help='List users')
    add_common_opts(ap_users, use_local=True)
    ap_users.set_defaults(func=lambda a: cmd_list(a, '(objectClass=inetOrgPerson)', ['uid','cn']))

    ap_groups = sub.add_parser('list-groups', help='List groups')
    add_common_opts(ap_groups, use_local=True)
    ap_groups.set_defaults(func=lambda a: cmd_list(
        a,
        '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))',
        ['cn','gidNumber']
    ))

    ap_fix = sub.add_parser('fix-posix-groups', help='Add posixGroup/gidNumber/memberUid based on member DN')
    add_common_opts(ap_fix, use_local=True)
    ap_fix.add_argument('--gid-offset', type=int, default=20000)
    ap_fix.add_argument('--gid-mod', type=int, default=40000)
    ap_fix.set_defaults(func=cmd_fix_posix_groups)

    ap_resync = sub.add_parser('resync-full', help='Clear contextCSN to force next full sync')
    add_common_opts(ap_resync, use_local=True)
    ap_resync.set_defaults(func=cmd_resync_full)

    ap_csn = sub.add_parser('show-csn', help='Show current contextCSN')
    add_common_opts(ap_csn, use_local=True)
    ap_csn.set_defaults(func=cmd_show_csn)

    args = ap.parse_args()
    if getattr(args, 'ssl', False):
        # ldaps 意味着禁用 starttls
        args.starttls = False
        if not str(args.uri).startswith("ldap"):
            args.uri = f"ldaps://{args.uri}"
    require_params(args, require_base=args.cmd in ('list-users','list-groups','resync-full','show-csn'))
    args.func(args)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
