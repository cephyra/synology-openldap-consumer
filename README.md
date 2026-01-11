# 群晖 OpenLDAP 同步镜像（Ubuntu）

轻量的 OpenLDAP consumer，专为从群晖 LDAP 同步数据（syncrepl）设计。无需额外脚本，修改 compose 环境变量即可运行。

[English](README-EN.md)

## 主要特性
- 基于 Ubuntu 22.04，预装 slapd/ldap-utils/python3-ldap3。
- 支持 SSL / StartTLS / 明文三种方式连接群晖 Provider。
- 内置自定义 schema 目录，可自动尝试获取 Provider schema（失败不影响启动）。
- 提供 `ldap-syncctl.py`：查看用户/组、显示 CSN、抓取 schema、重置本地库。
- 本地维护默认走 ldapi+EXTERNAL，不暴露本地管理员密码。

## 目录说明
- `Dockerfile`：构建镜像，内含 entrypoint、ldap-syncctl、默认 schema。
- `scripts/entrypoint.sh`：根据环境变量渲染 slapd.conf，配置 syncrepl，启动 slapd。
- `scripts/ldap-syncctl.py`：同步控制 CLI。
- `schema/custom/`：内置示例 schema（可选挂载替换）。
- `docker-compose.yml`：示例服务定义。

## 必填环境变量
- `LDAP_SERVER_ID`：节点 ID（rid）。
- `LDAP_BASE_DN`：如 `dc=example,dc=com`。
- `LDAP_LOCAL_ADMIN_USERNAME` / `LDAP_LOCAL_ADMIN_PASSWORD`：本地管理员账户/密码（用于 rootdn）。
- `LDAP_PROVIDER_URI`：群晖地址+端口，可不带协议前缀（如 `ldap.example.com:636`）。
- `LDAP_PROVIDER_BIND_DN` / `LDAP_PROVIDER_BIND_PW`：群晖同步账号。
- `LDAP_PROVIDER_SEARCHBASE`：同步搜索 Base。
- `LDAP_PROVIDER_SECURITY`：`ssl` / `starttls` / `none`。
- `LDAP_PROVIDER_TLS_REQCERT`：`demand` / `never`。
- `AUTO_FETCH_SCHEMA`：`true`/`false`，自动尝试 fetch schema。
- `SLAPD_LOG_LEVEL`：slapd 日志/调试级别关键字，默认 `stats`（可按需改成 `stats` / `sync` / `none` 等）。
- `CERT_CA`（默认 `/etc/ssl/certs/ca-certificates.crt`）：用于验证 Provider 证书（同时供本地 LDAPS 使用）。如使用群晖自签证书，请挂载 Provider CA，例如 `./certs/ca.cer:/certs/ca.cer:ro`。
- `CERT_CRT` / `CERT_KEY`：本地 LDAPS 证书/私钥（默认路径 `/certs/ldap.crt` `/certs/ldap.key`），信任根依旧使用 `CERT_CA`。

## 可选
- 挂载 `/certs/ldap.crt` `/certs/ldap.key` 以启用本地 LDAPS（信任根同样来自 `CERT_CA`）。
- 挂载 `/schema/custom` 覆盖默认 schema。

## 使用步骤
1. 编辑 `docker-compose.yml`，填入环境变量和（可选）证书。
2. 构建并启动：
   ```bash
   docker compose up -d
   ```
3. 验证（容器内）：
   ```bash
   docker compose exec ldap-01 ldap-syncctl.py list-users --tls-reqcert=never
   docker compose exec ldap-01 ldap-syncctl.py show-csn --tls-reqcert=never
   ```
4. 强制全量同步：
   ```bash
   docker compose exec ldap-01 ldap-syncctl.py resync-full
   docker compose restart ldap-01   # 可选，加快重新同步
   ```

## 安全与隐私
- 仓库仅保留示例值，请替换为自己的域名/账号/密码。
- 调试可将 `LDAP_PROVIDER_TLS_REQCERT` 设为 `never`；生产建议提供 CA 并使用 `demand`。

## 故障排查
- 认证失败：检查绑定账号密码、加密方式与端口。
- fetch-schema 无返回：群晖可能不允许读 subschema，可手动放 schema 至 `/schema/custom/provider.schema`。
- resync-full 失败：脚本会自动清空本地 DB，作为新节点重新拉取。
