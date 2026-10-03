# 一键安装与管理

这是 `xboard-node-rust` 的 Rust 节点安装流程。原版 Go 安装器和其他节点服务由各自的目录管理；本脚本只管理 `xboard-node-rust.service`。

## 准备

- Linux AMD64 或 ARM64，已运行 systemd，使用 root。推荐 Debian 12/13、Ubuntu 22.04/24.04。
- 已有 Xboard 面板和一个明确的节点 ID；v2 machine 模式还需要服务器 ID 与对应 token。
- 面板给该节点配置当前支持的 VLESS/Trojan/Shadowsocks；TCP 和协议内 UDP 已支持，原生 Rust 模式执行用户限速和来源 IP 限制。文件 TLS1.3 下的 VLESS Vision TCP 已支持，面板与客户端字段见[首页 Vision 配置](../README.md#vision-怎么用)。REALITY TCP 可带或不带 Vision，字段见[首页 REALITY 配置](../README.md#reality-怎么用)；普通 REALITY UDP 已支持；Vision UDP、mux 和其他未迁移配置会被拒绝。Shadowsocks 字段与密钥转换见[首页配置](../README.md#shadowsocks-怎么用)。
- 文件 TLS 需要已有证书和私钥文件，并在面板填入 file 证书配置。推荐放在 `/etc/ssl/` 或 `/etc/letsencrypt/`，本服务启用了 `ProtectHome=true`。
- 需要按面板设置开放节点端口；脚本不会修改防火墙或其他网络参数。

机器模式是 **machine 认证 + 一个固定节点**，此版不会自动枚举一台服务器的全部节点。

## 交互安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
```

输入面板根地址、节点 ID、服务器 ID 和隐藏的 token。legacy 模式把服务器 ID 留空，再填写面板要求的 `node_type`。安装完成后，用面板订阅和实际客户端验证转发。

没有 `curl` 时，Debian/Ubuntu 可先安装：

```bash
apt-get update
apt-get install -y ca-certificates curl
```

如果已经安装过，使用 `update` 或 `configure`；安装命令不会覆盖已有程序入口。卸载保留的数据可在再次安装时沿用，已有版本目录会核对全部文件后复用。

## 固定版本和自动安装

先下载安装器，再运行指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/v0.1.0-preview.6/install.sh -o install.sh
bash install.sh install --version v0.1.0-preview.6
```

自动化安装时，从权限为 0600 的文件或指定环境变量读取 token，避免把 token 直接写在命令参数中。例如先用编辑器准备 `/root/panel-token`：

```bash
bash install.sh install --yes \
  --panel https://panel.example.com --node-id 7 --machine-id 1 \
  --token-file /root/panel-token
```

旧 API 模式以 `--node-type vless` 等面板要求的值代替 `--machine-id`。两个选项不能一起使用。

`--no-start` 写入文件而不启动服务；在修改已运行配置或切换程序时，原服务会先停止，不会同时保留旧进程和新磁盘配置。

## 离线安装

从同一个 Release 下载对应架构的 `.tar.gz`、`SHA256SUMS` 与 `install.sh`，复制到目标 VPS：

```bash
bash install.sh install \
  --package xboard-node-rust-linux-amd64.tar.gz --checksums SHA256SUMS
```

ARM64 改用 `xboard-node-rust-linux-arm64.tar.gz`。归档在解压前校验，包内文件逐个校验，并核对 ELF 架构、项目和版本；路径穿越、符号链接条目和校验缺项会被拒绝。

若只需要把文件放入一个离线系统目录，可用 `--root /absolute/staging/path`。该模式隐含 `--no-start`，生成的路径对应这个目录，不对宿主机执行 systemctl；它不是一个新的在线实例模式。

## 管理命令

```bash
xboard-rust                 # 菜单
xboard-rust configure       # 重新配置；空 token 沿用已有 token
xboard-rust update          # 分页读取并按发布时间选择兼容版，含预览版
xboard-rust update --version v0.1.0-preview.6
xboard-rust rollback        # 上一个程序版本；检查声明的状态格式
xboard-rust start
xboard-rust stop
xboard-rust restart
xboard-rust status
xboard-rust logs
xboard-rust check
xboard-rust version
xboard-rust traffic-status  # 先 stop
xboard-rust uninstall
```

`configure` 在改动前把配置和凭据复制到私有备份目录；备份也包含秘密，分享时需要隐藏这些值。新配置或新程序启动检查失败时，恢复旧配置/程序，并尝试启动原服务。检查只覆盖本地设置和进程状态，面板兼容与真实转发需要另外验证。

升级和回退保留流量状态；如果两个版本声明不同的状态格式，会拒绝直接切换。即便格式相同，也不把状态回退到以前的内容，更不撤销已上报的流量。后续涉及状态迁移的版本须按发行说明处理。

## 卸载与保留数据

卸载会询问确认。自动执行可显式使用 `xboard-rust uninstall --yes`。

移除本服务、二进制命令链接、管理命令及当前程序链接；保留 `/etc/xboard-node-rust/`、`/var/lib/xboard-node-rust/` 和历史发行文件。这样可以保留凭据、待报流量与故障排查材料。脚本不删除真实面板数据。

## 常见情况

| 现象 | 检查方向 |
| --- | --- |
| 找不到对应架构下载 | 确认 Release 已公开，并包含这台 VPS 的 AMD64/ARM64 文件 |
| 安装路径已存在但无所有权标记 | 检查目录是谁创建的；不要为了安装覆盖他人的文件 |
| 本地检查成功，客户端仍不能连接 | 查看日志，确认面板配置/用户已获取、节点协议受支持、端口和证书可用 |
| 非零限制导致配置被拒绝 | 确认使用 preview.2 或更高的原生 Rust 模式；旧 preview.1 和可选外部内核 adapter 不执行这些限制，仍会拒绝 |
| 设置限速后单连接速率与预期不同 | 同一用户所有连接的上传和下载共用预算，单位是十进制 Mbps；有一秒突发额度，最小 64 KiB |
| 同一 IP 多设备仍能连接 | 限制统计本节点不同来源 IP，同一个公网 IP 共用名额，不能识别实际设备数量 |
| 文件证书不可读 | 检查文件路径与权限；`ProtectHome` 会隐藏家目录，私钥应放在服务可读取的位置 |
| 用户删除后旧连接还在 | 当前仅拒绝新认证；已认证会话不会被强制断开 |
| 上报批次显示 uncertain | 停机后用 `traffic-status` 看批次，先与实际面板记录核对；不盲目重发 |
| 服务重启后面板暂不可用 | 当前控制配置成功快照不跨整个主进程重启持久恢复，仍需重新拉取面板 |

HTTP 明文面板地址仅允许 literal 回环 IP，用于本地模拟面板测试；实际面板请使用 HTTPS。安装器不会禁用 TLS 校验。
