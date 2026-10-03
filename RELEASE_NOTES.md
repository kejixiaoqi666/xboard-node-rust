# Xboard Node Rust v0.1.0-preview.11

新增 **Shadowsocks 原生 Rust TCP/UDP**：传统 AEAD 的 AES-128-GCM、AES-256-GCM、ChaCha20-IETF-Poly1305，以及 2022 BLAKE3-AES-128/256-GCM。客户端按面板节点配置连接，服务端不依赖 Go/Xray 程序。保留此前的 VLESS/Trojan、REALITY、Vision TCP 和安装器。

## 安装器补丁

修复公开下载核查发现的实际问题：GitHub 发行列表可能不按发布时间排序，旧脚本会默认选到 preview.9。现在分页读取全部记录，先排除草稿、非法标签、无效发布时间和缺少当前架构文件的版本，再按发布时间与发行 ID 选择。固定 `--version` 保持不查列表。

新增五项实际安装器函数回归，覆盖乱序、架构缺失、草稿/无有效候选、第二页和固定版本；两架构各保留全部服务回归。

## 保留 preview.10 的补齐

- 用户密码与原 Go 节点一致；2022 使用 UUID 的 UTF-8 字节截断/零填充后 Base64 转换。派生密钥冲突会拒绝，具体字段见 [中文首页](README.md#shadowsocks-怎么用) / [English](README.en.md#configure-shadowsocks)。
- 认证、热更新、共享 TCP/UDP 限速、来源 IP 名额、直接/阻断路由、DNS 和持久有效载荷计数接入现有体系。TCP 可使用已有 SOCKS5 上游；UDP 不支持 SOCKS5 上游。
- TCP 握手、UDP 队列/关联/目标数和重放检查都有内存及时间边界。正常停机先取消并等待 UDP 数据写入者，再存档最终计数。
- 固定 MIT 帧库的 UDP 缓存改为按密钥内容索引，避免热更新后的地址复用；同时初始化 TCP/UDP 填充，防止空包带出缓冲区旧内容。保留原始许可、锁定版本与补丁来源。

## 安装与更新

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
xboard-rust update --version v0.1.0-preview.11
```

Linux AMD64 / ARM64 的静态 musl 发行包、一键管理脚本、SHA256 校验、第三方许可和安装/systemd 测试报告随发行版提供。Shadowsocks 的 TCP 与 UDP 监听相同端口，防火墙需要放行两者。

## 当前边界

仍是预览版。传统 Shadowsocks 最多 256 用户，2022 AES 最多 65,536 用户；2022 ChaCha、旧流密码、SIP003 插件和其他传输未迁移。缓存/队列上限和重放保留时间详见首页；它们不是实际承载量，也不跨重启保留。

REALITY 外层 PQ/HRR、Vision UDP、mux/XUDP、VMess、AnyTLS、TUIC、Hysteria2、规则集、加密 DNS、其他代理出站/代理链、SOCKS5 UDP、多节点、在线 IP 上报、ACME 和原 Go YAML 导入仍未完成。真实面板计费、公网承载与长期生产稳定性未验收；周期存档仍有强杀/断电尾部丢失窗口。本轮不宣称吞吐、CPU/内存改善或抗探测能力。

English: This preview adds native Rust Shadowsocks TCP/UDP for three traditional AEAD and two 2022 AES methods, preserving original panel key conversion and integrating live users, shared limits, routing and durable payload accounting. Bounded caches and owned UDP shutdown are documented in the bilingual README. Full upstream parity, production billing, WAN capacity and long-term stability are not claimed.
