# Xboard Node Rust v0.1.0-preview.6

增加 **原生 Rust VLESS REALITY TCP**，可带或不带 Vision，保留文件 TLS、TCP/UDP、路由/DNS、SOCKS5 TCP、共享限速、来源 IP 名额、持久流量统计和一键安装管理。

## 本版变化

- 面板 `tls=2` 和扁平 `tls_settings` 映射到原生 REALITY：X25519 密钥、单个 SNI、短 ID、时间差/客户端版本校验及固定目标站点。生成密钥命令与完整字段说明已加入中英文首页。
- REALITY + Vision 与不带 Vision 的 VLESS TCP；认证后仍使用原来的用户策略、目标路由和有效载荷计数。普通 TLS/认证失败连接只转发固定站点，不获得代理权限。
- 同一连接任务持有转发，停止时一起取消；10 秒握手、有限镜像记录和缓冲、最长 300 秒认证前转发，没有分离任务遗留。
- 采用 shoes 的固定 MIT 源码子集，以 ring/x25519-dalek 处理加密原语。独立审查修复短 ID 日志、握手后消息 panic、外层记录头未校验、Finished 类型/长度和缓冲边界；保留恶意消息与 close_notify 回归。Vision 读写接口不新增逐次堆分配。
- 双架构实际 systemd 安装使用固定官方 Xray v26.3.27 **客户端**验证 REALITY/文件 TLS、普通 TCP、内层 TLS1.2/1.3、双向 DIRECT、实际内层 HRR、错误 UUID/flow/短 ID 不连接目标、普通 TLS 固定站点转发和无 Vision VLESS。服务端不含或依赖 Xray。

## 安装与升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kejixiaoqi666/xboard-node-rust/main/install.sh) install
# 已安装：
xboard-rust update
```

AMD64/ARM64 静态 Linux 包、SHA256SUMS、构建来源、精确第三方许可及安装/systemd JSON 报告随附件提供。字段与限制见[中文首页](https://github.com/kejixiaoqi666/xboard-node-rust)和[English README](https://github.com/kejixiaoqi666/xboard-node-rust/blob/main/README.en.md)。

## 当前边界

仍是预览版。REALITY 外层要求单记录 ClientHello、TLS1.3/X25519 目标、非 HRR 的 ServerHello；外层 KeyUpdate、PQ 扩展、REALITY UDP、Vision UDP、mux/XUDP、其他协议/传输、GeoIP/GeoSite/规则集、加密 DNS、其他代理出站/代理链、SOCKS5 UDP、多节点、在线 IP 上报、自动 ACME 和原 Go YAML 导入仍未迁完。

认证前固定站点转发使用有界 DNS 后直接连接，不走用户 SOCKS5 路由、不计入用户有效载荷。DIRECT 仍使用有界 Tokio 复制，不宣称 splice/零拷贝、低 CPU、抗探测效果或最大承载。周期存档不保证强杀/断电尾部零丢失；未知上报与实际面板计费仍需对账，回环测试不代表长期公网稳定性。

回退 preview.5 或更早前先将面板和客户端改为旧版支持的 TLS/VLESS；回退 preview.3 或更早还须删除 Vision flow，preview.1/2 还须移除新路由/DNS/出站配置。升级/回退保留当前流量状态，不撤销计费。

English: Adds native Rust VLESS REALITY TCP with optional Vision, bounded owned mirror forwarding, strict configuration/authentication/TLS record validation, and preserved shared policy/routing/durable counters. Pinned official-client tests cover installed AMD64/ARM64 servers, inner TLS DIRECT/HRR, negative authentication and ordinary fixed-mirror TLS. Full parity, REALITY UDP, outer KeyUpdate/PQ/HRR, zero-copy, anti-probing, WAN capacity and production billing guarantees are not claimed.
