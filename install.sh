#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Xboard Rust node installer and local service manager.
set -Eeuo pipefail
umask 077

REPOSITORY=kejixiaoqi666/xboard-node-rust
UNIT=xboard-node-rust.service
# --root is an offline staging target. It never controls the host systemd service.
# shellcheck disable=SC2016
ROOT=
ACTION=${1:-menu}
[[ $# == 0 ]] || shift
VERSION=latest
PACKAGE=
CHECKSUMS=
PANEL=
NODE_ID=
MACHINE_ID=
NODE_TYPE=
TOKEN_FILE=
TOKEN_VAR=
YES=false
NO_START=false
WORK=
STAGED_FILES=()

fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
cleanup() {
    [[ -z ${WORK:-} ]] || rm -rf -- "$WORK"
    local path
    for path in "${STAGED_FILES[@]}"; do rm -f -- "$path"; done
}
trap cleanup EXIT

usage() {
    cat <<'HELP'
Xboard Rust 节点管理
  bash install.sh                         交互菜单
  bash install.sh install                 下载、配置并安装
  xboard-rust configure                   修改面板/节点配置
  xboard-rust update [--version v...]      更新程序，保留配置和流量数据
  xboard-rust rollback                    回退到上一程序版本
  xboard-rust start|stop|restart|status    管理本服务
  xboard-rust logs                        最近日志
  xboard-rust version                     发行版、目标架构、程序校验值
  xboard-rust check                       本地配置检查，不联系面板
  xboard-rust traffic-status              停机后查看本地待报流量
  xboard-rust uninstall                   卸载服务/命令，保留配置和数据

安装/配置选项：
  --panel URL --node-id N --machine-id N  Xboard v2 machine 认证
  --node-type TYPE                       legacy 模式，如 vless/trojan；与 machine-id 互斥
  --token-file FILE                      从文件读取 token，不放入命令行
  --token-env NAME                       从指定环境变量读取 token
  --yes                                 不询问；配置字段必须完整
  --no-start                            写入文件但不启动服务
  --version TAG                         固定发行版；默认最新已发布版，含预览版
  --package FILE --checksums FILE        使用离线发行包和官方 SHA256SUMS
  --root ABSOLUTE_PATH                   离线安装目录，隐含 --no-start；不操作 systemd

支持 Linux AMD64/ARM64 + systemd。默认使用 Rust 内置数据层。
当前支持 VLESS/Trojan TCP、文件 TLS；其他协议/限制请先看 README。
HELP
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version|--package|--checksums|--panel|--node-id|--machine-id|--node-type|--token-file|--token-env|--root)
            [[ $# -ge 2 ]] || fail "$1 缺少参数"
            value=$2
            case "$1" in
                --version) VERSION=$value;; --package) PACKAGE=$value;; --checksums) CHECKSUMS=$value;;
                --panel) PANEL=$value;; --node-id) NODE_ID=$value;; --machine-id) MACHINE_ID=$value;;
                --node-type) NODE_TYPE=$value;; --token-file) TOKEN_FILE=$value;; --token-env) TOKEN_VAR=$value;;
                --root) ROOT=$value; NO_START=true;;
            esac
            shift 2;;
        --yes) YES=true; shift;;
        --no-start) NO_START=true; shift;;
        --help|-h) usage; exit 0;;
        *) fail "未知选项：$1";;
    esac
done
[[ $ACTION != --help && $ACTION != -h ]] || { usage; exit 0; }
case "$ACTION" in menu|install|configure|update|rollback|start|stop|restart|status|logs|version|check|traffic-status|uninstall) ;; *) usage; fail "未知命令：$ACTION";; esac
[[ $EUID == 0 ]] || fail '请以 root 或 sudo 执行'
[[ $(uname -s) == Linux ]] || fail '仅支持 Linux'
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) fail '仅支持 AMD64/ARM64';; esac
if [[ -n $ROOT ]]; then
    [[ $ROOT == /* && $ROOT != / && $ROOT != *$'\n'* && $ROOT != *$'\r'* && $ROOT != *' '* ]] || fail '--root 必须是非根绝对路径，不能包含空格或换行'
    ROOT=${ROOT%/}
    command -v python3 >/dev/null || fail '离线目录模式需要 python3'
    resolved=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$ROOT")
    [[ $resolved == "$ROOT" ]] || fail '--root 不允许符号链接或 .. 路径'
else
    [[ -d /run/systemd/system ]] || fail '需要正在运行的 systemd 系统'
fi
CONFIG_DIR=$ROOT/etc/xboard-node-rust
STATE_DIR=$ROOT/var/lib/xboard-node-rust
LIB_DIR=$ROOT/usr/local/lib/xboard-node-rust
CURRENT=$LIB_DIR/current
MANAGER=$ROOT/usr/local/bin/xboard-rust
LINK=$ROOT/usr/local/bin/xboard-node-rust
UNIT_PATH=$ROOT/etc/systemd/system/$UNIT
CONFIG=$CONFIG_DIR/runtime.json
ENV_FILE=$CONFIG_DIR/panel.env
MARKER=$CONFIG_DIR/.managed-by

dependencies() {
    local missing=false
    for command in curl python3 tar sha256sum flock; do
        command -v "$command" >/dev/null || missing=true
    done
    if $missing; then
        [[ -z $ROOT ]] || fail '离线模式需要 curl、python3、tar、sha256sum、flock'
        if command -v apt-get >/dev/null; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl python3 tar coreutils util-linux
        else
            fail '请先安装 ca-certificates、curl、python3、tar、coreutils、util-linux'
        fi
    fi
}

owned() {
    [[ -f $MARKER && ! -L $MARKER ]] || fail '未找到本安装器的所有权标记；拒绝修改已有目录'
    [[ $(cat "$MARKER") == "$REPOSITORY" ]] || fail '目录由其他项目管理'
}

paths_safe() {
    local p
    for p in "$CONFIG_DIR" "$CONFIG_DIR/backups" "$STATE_DIR" "$LIB_DIR" "$LIB_DIR/releases" "$UNIT_PATH" "$CONFIG" "$ENV_FILE" "$MANAGER" "$LIB_DIR/previous" "$ROOT/run/lock" "$ROOT/run/lock/xboard-node-rust.lock"; do
        [[ ! -L $p ]] || fail "拒绝修改符号链接：$p"
    done
    # Validate all parent components, including /usr/local/lib and staging roots.
    python3 - "$CONFIG_DIR" "$CONFIG_DIR/backups" "$STATE_DIR" "$LIB_DIR" "$LIB_DIR/releases" "$UNIT_PATH" "$MANAGER" "$LINK" "$ROOT/run/lock/xboard-node-rust.lock" <<'PY'
import pathlib, sys
for name in sys.argv[1:]:
    p = pathlib.Path(name)
    if any(parent.is_symlink() for parent in p.parents):
        sys.exit('安装路径的父目录包含符号链接')
PY
}

owned_entries() {
    python3 - "$LIB_DIR" "$CURRENT" "$MANAGER" "$UNIT_PATH" "$CONFIG" "$ENV_FILE" "$LINK" <<'PY'
import hashlib, json, pathlib, re, sys
lib, current, manager, unit, config, env, link = map(pathlib.Path, sys.argv[1:])
if current.exists() or current.is_symlink():
    if not current.is_symlink(): sys.exit('当前程序入口不是本安装器的链接')
    target = current.resolve()
    if target.parent != lib / 'releases' or not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?', target.name):
        sys.exit('当前程序链接不属于本安装器')
    meta = json.loads((target / 'BUILDINFO.json').read_text())
    if meta.get('repository') != 'kejixiaoqi666/xboard-node-rust': sys.exit('当前程序来源不同')
    if manager.exists() and manager.read_bytes() != (target / 'install.sh').read_bytes():
        sys.exit('管理命令已被修改或由其他项目接管，拒绝覆盖/删除')
elif manager.exists() or unit.exists() or link.exists() or link.is_symlink():
    sys.exit('遗留标记不足以证明现有入口归属，拒绝覆盖/删除')
if link.exists() or link.is_symlink():
    if not link.is_symlink() or link.readlink() != current / 'bin/xboard-node-rust':
        sys.exit('二进制命令不属于本安装器')
if unit.exists():
    text = unit.read_text().splitlines()
    expected = ['Description=Xboard Rust node', 'ExecStart=' + str(current / 'bin/xboard-node-rust') + ' --config ' + str(config), 'EnvironmentFile=' + str(env)]
    if any(text.count(line) != 1 for line in expected):
        sys.exit('服务文件已被其他项目接管，拒绝覆盖/删除')
PY
    if [[ -L $CURRENT ]]; then validate_release "$(readlink -f -- "$CURRENT")"; fi
}

validate_release() {
    python3 - "$LIB_DIR/releases" "$1" <<'PY'
import hashlib, json, pathlib, re, sys
base, target = map(pathlib.Path, sys.argv[1:])
if target.is_symlink() or target.resolve() != target or target.parent != base or not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?', target.name):
    sys.exit('版本路径超出 releases 或含符号链接/非规范路径')
actual = {}
for path in target.rglob('*'):
    if path.is_symlink(): sys.exit('版本目录包含符号链接')
    if path.is_file(): actual[path.relative_to(target).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
checks = {}
for line in (target / 'SHA256SUMS').read_text().splitlines():
    match = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line)
    if not match or match[2] in checks: sys.exit('版本校验清单不合法')
    checks[match[2]] = match[1]
if set(checks) != set(actual) - {'SHA256SUMS'} or any(actual.get(name) != digest for name, digest in checks.items()):
    sys.exit('版本文件发生变化，拒绝执行或切换')
meta = json.loads((target / 'BUILDINFO.json').read_text())
if meta.get('repository') != 'kejixiaoqi666/xboard-node-rust' or meta.get('version') != target.name:
    sys.exit('版本来源不匹配')
PY
}

lock() {
    local lock_dir=$ROOT/run/lock
    install -d -m 755 "$lock_dir"
    [[ ! -L $lock_dir/xboard-node-rust.lock ]] || fail '锁文件不能是符号链接'
    exec 9>"$lock_dir/xboard-node-rust.lock"
    flock -n 9 || fail '另一个安装/管理任务正在运行'
}

make_work() { WORK=$(mktemp -d "${TMPDIR:-/tmp}/xboard-rust.XXXXXXXX"); }
fetch() { curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 "$1" -o "$2"; }

select_version() {
    if [[ $VERSION == latest ]]; then
        fetch "https://api.github.com/repos/$REPOSITORY/releases?per_page=20" "$WORK/releases.json"
        VERSION=$(python3 - "$WORK/releases.json" "$ARCH" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))
required = {'SHA256SUMS', 'xboard-node-rust-linux-' + sys.argv[2] + '.tar.gz'}
for release in items:
    if not release.get('draft') and required <= {x['name'] for x in release.get('assets', [])}:
        print(release['tag_name']); break
else:
    sys.exit('没有此架构的可下载发行版')
PY
        )
    fi
    [[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$ ]] || fail '发行版标签不合法'
}

prepare_package() {
    make_work
    local asset=xboard-node-rust-linux-$ARCH.tar.gz
    if [[ -n $PACKAGE ]]; then
        [[ -n $CHECKSUMS && -f $PACKAGE && -f $CHECKSUMS ]] || fail '离线包必须同时提供 --package 和 --checksums'
        cp -- "$PACKAGE" "$WORK/$asset"
        cp -- "$CHECKSUMS" "$WORK/SHA256SUMS"
    else
        [[ -z $CHECKSUMS ]] || fail '--checksums 仅与 --package 一起使用'
        select_version
        fetch "https://github.com/$REPOSITORY/releases/download/$VERSION/$asset" "$WORK/$asset"
        fetch "https://github.com/$REPOSITORY/releases/download/$VERSION/SHA256SUMS" "$WORK/SHA256SUMS"
    fi
    # No extraction occurs until the exact named asset has been verified.
    python3 - "$WORK" "$asset" "$ARCH" "$VERSION" <<'PY'
import hashlib, json, os, pathlib, re, struct, sys, tarfile
work, asset, arch, requested = pathlib.Path(sys.argv[1]), *sys.argv[2:]
matches = []
for line in (work / 'SHA256SUMS').read_text().splitlines():
    match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](\S+)', line)
    if match and match[2] == asset:
        matches.append(match[1].lower())
if len(matches) != 1 or hashlib.sha256((work / asset).read_bytes()).hexdigest() != matches[0]:
    sys.exit('发行包 SHA-256 不匹配或校验项不唯一')
dest = work / 'payload'
dest.mkdir(mode=0o700)
with tarfile.open(work / asset, 'r:gz') as tar:
    members = tar.getmembers()
    if not 4 <= len(members) <= 1024 or sum(m.size for m in members) > 128 * 1024 * 1024:
        sys.exit('发行包规模异常')
    names = set()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if not member.isfile() or path.is_absolute() or '..' in path.parts or '\\' in member.name or path.parts[0] != 'xboard-node-rust':
            sys.exit('发行包包含不安全条目')
        rel = pathlib.PurePosixPath(*path.parts[1:])
        if not rel.parts or rel.as_posix() in names:
            sys.exit('发行包条目重复或为空')
        names.add(rel.as_posix())
        out = dest.joinpath(*rel.parts)
        out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tar.extractfile(member) as src, out.open('xb') as target:
            target.write(src.read())
        out.chmod(0o755 if rel.as_posix() in ['bin/xboard-node-rust', 'install.sh'] else 0o644)
required = {'bin/xboard-node-rust', 'install.sh', 'VERSION', 'BUILDINFO.json', 'LICENSE', 'third-party-notices.tar.gz', 'SHA256SUMS'}
if not required <= names:
    sys.exit('发行包缺少文件')
checks = {}
for line in (dest / 'SHA256SUMS').read_text().splitlines():
    match = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line)
    if not match or match[2] not in names or match[2] == 'SHA256SUMS' or match[2] in checks:
        sys.exit('包内校验清单不合法')
    checks[match[2]] = match[1]
if set(checks) != names - {'SHA256SUMS'}:
    sys.exit('包内校验清单不完整')
for name, expected in checks.items():
    if hashlib.sha256((dest / name).read_bytes()).hexdigest() != expected:
        sys.exit('包内文件校验失败：' + name)
meta = json.loads((dest / 'BUILDINFO.json').read_text())
version = (dest / 'VERSION').read_text().strip()
if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?', version) or meta['version'] != version:
    sys.exit('发行包版本不匹配')
if requested != 'latest' and requested != version:
    sys.exit('下载的版本与指定版本不匹配')
if meta['architecture'] != arch or meta.get('repository') != 'kejixiaoqi666/xboard-node-rust':
    sys.exit('发行包架构或项目不匹配')
binary = (dest / 'bin/xboard-node-rust').read_bytes()
machine = 62 if arch == 'amd64' else 183
if len(binary) < 64 or binary[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', binary, 18)[0] != machine:
    sys.exit('程序 ELF 架构不匹配')
if meta['libc'] == 'gnu':
    try:
        actual = tuple(map(int, os.confstr('CS_GNU_LIBC_VERSION').split()[1].split('.')))
        required = tuple(map(int, meta['minimum_glibc'].split('.')))
    except (ValueError, AttributeError):
        sys.exit('该 GNU 包需要 glibc 系统')
    if actual < required:
        sys.exit('系统 glibc 低于发行包要求')
elif meta['libc'] != 'musl':
    sys.exit('未知 libc 类型')
print('发行包及全部文件校验通过：' + version + ' / ' + arch)
PY
    VERSION=$(cat "$WORK/payload/VERSION")
    "$WORK/payload/bin/xboard-node-rust" --help >/dev/null || fail '候选程序无法在本机执行'
}

unit_write() {
    install -d -m 755 "$(dirname "$UNIT_PATH")"
    cat > "$UNIT_PATH" <<SERVICE
[Unit]
Description=Xboard Rust node
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=root
EnvironmentFile=$ENV_FILE
ExecStart=$CURRENT/bin/xboard-node-rust --config $CONFIG
WorkingDirectory=$STATE_DIR
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=mixed
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
SERVICE
    chmod 644 "$UNIT_PATH"
}

switch_current() {
    local target=$1
    validate_release "$target" || return 1
    if [[ -L $CURRENT && $(readlink -- "$CURRENT") == "$target" ]]; then return 0; fi
    ln -s -- "$target" "$LIB_DIR/.current.$$" || return 1
    if ! mv -Tf -- "$LIB_DIR/.current.$$" "$CURRENT"; then
        rm -f -- "$LIB_DIR/.current.$$"
        return 1
    fi
}

start_service() {
    # Explicit operator actions may follow many starts in a short time. Keep the
    # automatic crash-loop limit, but clear this unit's counter before recovery.
    systemctl reset-failed "$UNIT" || return 1
    systemctl start "$UNIT"
}

activate() {
    if [[ -n $ROOT ]] || $NO_START; then
        say '文件已准备，服务未启动。'
        return 0
    fi
    systemctl daemon-reload || return 1
    systemctl enable "$UNIT" >/dev/null || return 1
    start_service || return 1
    sleep 2
    systemctl is-active --quiet "$UNIT"
}

credentials() {
    INSTALL_TOKEN=
    [[ -z $TOKEN_FILE || -z $TOKEN_VAR ]] || fail '--token-file 和 --token-env 不能一起使用'
    if [[ -n $TOKEN_FILE ]]; then
        [[ -f $TOKEN_FILE && ! -L $TOKEN_FILE ]] || fail 'token 文件不存在或是符号链接'
        INSTALL_TOKEN=$(cat -- "$TOKEN_FILE")
    elif [[ -n $TOKEN_VAR ]]; then
        [[ $TOKEN_VAR =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail '环境变量名不合法'
        INSTALL_TOKEN=${!TOKEN_VAR:-}
    elif ! $YES; then
        read -r -s -u 3 -p '面板 token（输入隐藏；已有配置可留空沿用）：' INSTALL_TOKEN
        printf '\n' >&3
    fi
    [[ -n $INSTALL_TOKEN || -f $ENV_FILE ]] || fail 'token 不能为空；无交互时请用 --token-file 或 --token-env'
    export INSTALL_TOKEN
}

prepare_config() {
    mkdir -p "$WORK/config"
    if ! $YES; then
        exec 3<>/dev/tty || fail '需要交互终端；自动安装请用 --yes 并提供完整参数'
        if [[ -z $PANEL ]]; then read -r -u 3 -p '面板根地址（HTTPS；已有配置可留空沿用）：' PANEL; fi
        if [[ -z $NODE_ID ]]; then read -r -u 3 -p '节点 ID（不是服务器 ID；已有配置可留空）：' NODE_ID; fi
        if [[ -z $MACHINE_ID && -z $NODE_TYPE && ! -f $CONFIG ]]; then
            read -r -u 3 -p '服务器 ID（v2 machine 模式；legacy 模式留空）：' MACHINE_ID
            if [[ -z $MACHINE_ID ]]; then read -r -u 3 -p 'legacy node_type（例如 vless、trojan）：' NODE_TYPE; fi
        fi
    fi
    [[ -z $MACHINE_ID || -z $NODE_TYPE ]] || fail 'machine-id 与 node-type 互斥'
    credentials
    export INSTALL_PANEL=$PANEL INSTALL_NODE=$NODE_ID INSTALL_MACHINE=$MACHINE_ID INSTALL_TYPE=$NODE_TYPE
    python3 - "$CONFIG" "$ENV_FILE" "$WORK/config" "$STATE_DIR" <<'PY'
import ipaddress, json, os, pathlib, re, sys, urllib.parse
current, env_file, dest, state = map(pathlib.Path, sys.argv[1:])
config = json.loads(current.read_text()) if current.exists() else {
    'poll_seconds': 30, 'report_seconds': 60, 'traffic_checkpoint_ms': 1000,
    'websocket': True, 'native_user_updates': True, 'traffic_reporting': True,
}
config['panel_url'] = os.environ['INSTALL_PANEL'] or config.get('panel_url', '')
url = urllib.parse.urlsplit(config['panel_url'])
try:
    loopback = ipaddress.ip_address(url.hostname or '').is_loopback
except ValueError:
    loopback = False
if (url.scheme != 'https' and not (url.scheme == 'http' and loopback)) or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ['', '/']:
    sys.exit('请输入 HTTPS 面板根地址；HTTP 仅支持回环地址测试，不含路径/凭据/查询参数')
try:
    url.port
    if any(ch.isspace() or ord(ch) < 32 for ch in config['panel_url']):
        raise ValueError()
except ValueError:
    sys.exit('面板地址格式不合法')
config['panel_url'] = config['panel_url'].rstrip('/')
node = os.environ['INSTALL_NODE']
if node:
    if not re.fullmatch(r'[1-9][0-9]*', node): sys.exit('节点 ID 必须是正整数')
    config['node_id'] = int(node)
if not isinstance(config.get('node_id'), int) or not 1 <= config['node_id'] <= 4294967295:
    sys.exit('节点 ID 必须在 1..4294967295')
machine, kind = os.environ['INSTALL_MACHINE'], os.environ['INSTALL_TYPE']
if machine:
    if not re.fullmatch(r'[1-9][0-9]*', machine) or not 1 <= int(machine) <= 4294967295:
        sys.exit('服务器 ID 必须在 1..4294967295')
    config['machine_id'] = int(machine)
    config.pop('node_type', None)
if kind:
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', kind): sys.exit('node_type 格式不合法')
    config.pop('machine_id', None)
    config['node_type'] = kind
if not config.get('machine_id') and not config.get('node_type'):
    sys.exit('请提供 machine-id 或 legacy node-type')
config.update(state_dir=str(state), token_env='XBORD_PANEL_TOKEN', allow_loopback_http=(url.scheme == 'http' and loopback))
config.pop('singbox_executable', None)
token = os.environ['INSTALL_TOKEN']
if token:
    if len(token.encode()) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in token):
        sys.exit('token 太长或包含控制字符')
    quoted = token.replace('\\', '\\\\').replace('"', '\\"')
    (dest / 'panel.env').write_text('XBORD_PANEL_TOKEN="' + quoted + '"\n')
else:
    (dest / 'panel.env').write_bytes(env_file.read_bytes())
(dest / 'runtime.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
for path in dest.iterdir(): path.chmod(0o600)
PY
    unset INSTALL_TOKEN
    local binary=${1:-$CURRENT/bin/xboard-node-rust}
    "$binary" --config "$WORK/config/runtime.json" --check >/dev/null || fail '本地配置校验失败'
}

backup_config() {
    local backup
    backup=$CONFIG_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$
    install -d -m 700 "$backup"
    [[ ! -f $CONFIG ]] || install -m 600 "$CONFIG" "$backup/runtime.json"
    [[ ! -f $ENV_FILE ]] || install -m 600 "$ENV_FILE" "$backup/panel.env"
    BACKUP=$backup
}

config_write() {
    install -m 600 "$WORK/config/runtime.json" "$CONFIG" || return 1
    install -m 600 "$WORK/config/panel.env" "$ENV_FILE" || return 1
}

stage_release() {
    local destination=$LIB_DIR/releases/$VERSION
    if [[ -e $destination || -L $destination ]]; then
        python3 - "$WORK/payload" "$destination" <<'PY'
import hashlib, pathlib, sys
def inventory(name):
    root = pathlib.Path(name)
    if root.is_symlink() or not root.is_dir(): sys.exit('保留版本目录不合法')
    result = {}
    for path in root.rglob('*'):
        if path.is_symlink(): sys.exit('保留版本包含符号链接')
        if path.is_file(): result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result
if inventory(sys.argv[1]) != inventory(sys.argv[2]):
    sys.exit('保留版本与发行包不一致，拒绝覆盖；请检查文件')
PY
    else
        cp -a "$WORK/payload" "$destination"
    fi
}

same_state_format() {
    python3 - "$1/BUILDINFO.json" "$2/BUILDINFO.json" <<'PY'
import json, sys
old, new = (json.load(open(path)) for path in sys.argv[1:])
if not old.get('state_format') or old['state_format'] != new.get('state_format'):
    sys.exit('版本的状态格式不同；请按发行说明迁移，不能直接回退或更新')
PY
}

prepare_switch_metadata() {
    local next=$1 previous=$2
    NEXT_MANAGER=$(mktemp "$ROOT/usr/local/bin/.xboard-rust.next.XXXXXXXX")
    STAGED_FILES+=("$NEXT_MANAGER")
    RESTORE_MANAGER=$(mktemp "$ROOT/usr/local/bin/.xboard-rust.restore.XXXXXXXX")
    STAGED_FILES+=("$RESTORE_MANAGER")
    NEXT_PREVIOUS=$(mktemp "$LIB_DIR/.previous.next.XXXXXXXX")
    STAGED_FILES+=("$NEXT_PREVIOUS")
    RESTORE_PREVIOUS=$(mktemp "$LIB_DIR/.previous.restore.XXXXXXXX")
    STAGED_FILES+=("$RESTORE_PREVIOUS")
    install -m 755 "$next/install.sh" "$NEXT_MANAGER"
    install -m 755 "$MANAGER" "$RESTORE_MANAGER"
    printf '%s\n' "$previous" > "$NEXT_PREVIOUS"
    HAD_PREVIOUS=false
    if [[ -f $LIB_DIR/previous ]]; then
        HAD_PREVIOUS=true
        cp -- "$LIB_DIR/previous" "$RESTORE_PREVIOUS"
    fi
}

commit_switch_metadata() {
    mv -Tf -- "$NEXT_MANAGER" "$MANAGER" || return 1
    mv -Tf -- "$NEXT_PREVIOUS" "$LIB_DIR/previous" || return 1
}

restore_switch_metadata() {
    mv -Tf -- "$RESTORE_MANAGER" "$MANAGER" || return 1
    if $HAD_PREVIOUS; then
        mv -Tf -- "$RESTORE_PREVIOUS" "$LIB_DIR/previous" || return 1
    else
        rm -f -- "$LIB_DIR/previous" || return 1
    fi
}

install_node() {
    dependencies; paths_safe; lock
    [[ ! -e $CURRENT && ! -L $CURRENT && ! -e $LINK && ! -L $LINK && ! -e $MANAGER && ! -e $UNIT_PATH ]] || fail '已有安装；请使用 update/configure'
    if [[ -e $CONFIG_DIR || -e $STATE_DIR || -e $LIB_DIR ]]; then owned; fi
    prepare_package
    prepare_config "$WORK/payload/bin/xboard-node-rust"
    install -d -m 700 "$CONFIG_DIR" "$STATE_DIR"
    install -d -m 755 "$LIB_DIR/releases" "$ROOT/usr/local/bin"
    stage_release
    printf '%s\n' "$REPOSITORY" > "$MARKER"
    chmod 600 "$MARKER"
    if [[ -f $CONFIG || -f $ENV_FILE ]]; then backup_config; fi
    config_write
    switch_current "$LIB_DIR/releases/$VERSION"
    ln -s -- "$CURRENT/bin/xboard-node-rust" "$LINK"
    install -m 755 "$CURRENT/install.sh" "$MANAGER"
    unit_write
    if ! activate; then
        systemctl disable --now "$UNIT" || true
        fail '服务启动失败；配置/数据已保留，运行 xboard-rust logs 查看。服务 active 也不代表协议已连通。'
    fi
    say "已安装 $VERSION ($ARCH)。管理菜单：xboard-rust"
    say "配置：$CONFIG；凭据：$ENV_FILE（0600）；状态：$STATE_DIR"
    say '请使用真实客户端测试面板对应节点。脚本不自动修改防火墙或放行端口。'
}

configure_node() {
    dependencies; paths_safe; owned; lock; owned_entries; make_work
    [[ -x $CURRENT/bin/xboard-node-rust ]] || fail '请先安装程序'
    prepare_config
    backup_config
    local was_active=false
    if [[ -z $ROOT ]] && systemctl is-active --quiet "$UNIT"; then was_active=true; systemctl stop "$UNIT"; fi
    if ! config_write || ! activate; then
        if [[ -z $ROOT ]]; then systemctl stop "$UNIT" || true; fi
        install -m 600 "$BACKUP/runtime.json" "$CONFIG" || fail '配置恢复失败；服务保持停止，请从私有备份恢复'
        install -m 600 "$BACKUP/panel.env" "$ENV_FILE" || fail '凭据恢复失败；服务保持停止，请从私有备份恢复'
        if $was_active; then start_service || true; fi
        fail '新配置未启动，已恢复原配置。请查看日志并核对面板支持范围。'
    fi
    say '配置已保存。本地检查只验证配置格式；请另测实际节点连接。'
}

update_node() {
    dependencies; paths_safe; owned; lock; owned_entries
    [[ -L $CURRENT && -f $CONFIG ]] || fail '请先安装'
    local previous
    previous=$(readlink -f -- "$CURRENT")
    [[ $previous == "$LIB_DIR"/releases/v* ]] || fail '现有程序路径不属于本安装器'
    prepare_package
    [[ $previous != "$LIB_DIR/releases/$VERSION" ]] || { say "已经是 $VERSION"; return; }
    same_state_format "$previous" "$WORK/payload"
    "$WORK/payload/bin/xboard-node-rust" --config "$CONFIG" --check >/dev/null || fail '新版本不接受当前配置'
    stage_release
    prepare_switch_metadata "$LIB_DIR/releases/$VERSION" "$previous"
    local was_active=false
    if [[ -z $ROOT ]] && systemctl is-active --quiet "$UNIT"; then was_active=true; systemctl stop "$UNIT"; fi
    if ! switch_current "$LIB_DIR/releases/$VERSION" || ! commit_switch_metadata || ! activate; then
        if [[ -z $ROOT ]]; then systemctl stop "$UNIT" || true; fi
        switch_current "$previous" || fail '旧程序链接恢复失败；服务保持停止，请检查版本目录'
        restore_switch_metadata || fail '管理入口恢复失败；服务保持停止，请检查备份文件'
        if $was_active; then start_service || true; fi
        fail '新版本启动失败，已恢复原程序链接；配置和流量数据保持原位'
    fi
    say "已更新到 $VERSION。回退：xboard-rust rollback"
    say '程序回退不回滚计费/持久状态；跨版本状态兼容要求见对应发行说明。'
}

rollback_node() {
    dependencies; paths_safe; owned; lock; owned_entries
    [[ -f $LIB_DIR/previous && ! -L $LIB_DIR/previous ]] || fail '没有上一版本'
    local previous current
    previous=$(cat "$LIB_DIR/previous")
    current=$(readlink -f -- "$CURRENT")
    validate_release "$previous" || fail '回退路径或文件不属于本安装器'
    same_state_format "$current" "$previous"
    "$previous/bin/xboard-node-rust" --config "$CONFIG" --check >/dev/null || fail '旧程序不接受当前配置'
    prepare_switch_metadata "$previous" "$current"
    local was_active=false
    if [[ -z $ROOT ]] && systemctl is-active --quiet "$UNIT"; then was_active=true; systemctl stop "$UNIT"; fi
    if ! switch_current "$previous" || ! commit_switch_metadata || ! activate; then
        if [[ -z $ROOT ]]; then systemctl stop "$UNIT" || true; fi
        switch_current "$current" || fail '当前程序链接恢复失败；服务保持停止，请检查版本目录'
        restore_switch_metadata || fail '管理入口恢复失败；服务保持停止，请检查备份文件'
        if $was_active; then start_service || true; fi
        fail '回退程序未启动，已恢复当前程序链接'
    fi
    say "程序已回退至 $(cat "$CURRENT/VERSION")；配置和流量数据未回滚。"
}

uninstall_node() {
    dependencies; paths_safe; owned; lock; owned_entries
    if ! $YES; then
        exec 3<>/dev/tty || fail '需要交互确认；自动卸载使用 --yes'
        read -r -u 3 -p '卸载本服务和管理命令，保留配置、凭据、状态及历史程序？[y/N]：' answer
        [[ $answer == y || $answer == Y ]] || { say '已取消'; return; }
    fi
    [[ ! -e $LINK && ! -L $LINK ]] || [[ -L $LINK && $(readlink -- "$LINK") == "$CURRENT/bin/xboard-node-rust" ]] || fail '二进制入口不属于本安装器'
    if [[ -z $ROOT ]]; then systemctl disable --now "$UNIT"; fi
    rm -f -- "$UNIT_PATH" "$LINK" "$MANAGER" "$CURRENT"
    if [[ -z $ROOT ]]; then systemctl daemon-reload; fi
    say '本服务和命令已卸载。配置、凭据、流量状态和历史程序均已保留。'
    say "保留位置：$CONFIG_DIR、$STATE_DIR、$LIB_DIR"
}

service_action() {
    owned
    [[ -z $ROOT ]] || fail '离线目录模式不控制系统服务'
    case "$ACTION" in
        start|stop|restart)
            dependencies; paths_safe; lock; owned_entries
            if [[ $ACTION != stop ]]; then systemctl reset-failed "$UNIT"; fi
            systemctl "$ACTION" "$UNIT"
            ;;
        status) systemctl status "$UNIT" --no-pager --full;;
        logs) journalctl -u "$UNIT" -n 100 --no-pager;;
    esac
}

menu() {
    exec 3<>/dev/tty || fail '菜单需要交互终端；可指定 install 命令'
    cat >&3 <<'MENU'
Xboard Rust 节点
1) 安装       2) 更新       3) 修改配置    4) 程序回退
5) 启动       6) 停止       7) 重启        8) 状态
9) 日志      10) 版本      11) 配置检查   12) 卸载
0) 退出
MENU
    read -r -u 3 -p '请选择：' choice
    case "$choice" in
        1) ACTION=install;; 2) ACTION=update;; 3) ACTION=configure;; 4) ACTION=rollback;;
        5) ACTION=start;; 6) ACTION=stop;; 7) ACTION=restart;; 8) ACTION=status;;
        9) ACTION=logs;; 10) ACTION=version;; 11) ACTION=check;; 12) ACTION=uninstall;;
        0) exit 0;; *) fail '请选择菜单中的数字';;
    esac
}

[[ $ACTION != menu ]] || menu
case "$ACTION" in
    install) install_node;; configure) configure_node;; update) update_node;; rollback) rollback_node;;
    uninstall) uninstall_node;; start|stop|restart|status|logs) service_action;;
    version) owned; cat "$CURRENT/BUILDINFO.json"; sha256sum "$CURRENT/bin/xboard-node-rust";;
    check) owned; "$CURRENT/bin/xboard-node-rust" --config "$CONFIG" --check;;
    traffic-status)
        owned
        [[ -n $ROOT ]] || ! systemctl is-active --quiet "$UNIT" || fail '请先停止服务再读取流量队列'
        "$CURRENT/bin/xboard-node-rust" --config "$CONFIG" --traffic-status;;
esac
