# Silent Speaker

[English](#english) | [中文](#中文)

---

## English

**Silent Speaker** is a high-performance, security-focused implementation of the **fengni** protocol. Built on top of QUIC, it is designed to be highly resistant to traffic analysis and network instability.

### The fengni Protocol
**fengni** (pronounced like *"funny"*) refers to the core architectural design of this system. The name is derived from the Chinese word **"封泥" (fēng ní)**, which refers to the "Clay Seals" used in ancient China to protect the privacy of official correspondences and documents. 

Like its namesake, the **fengni** protocol ensures that the structure and content of your digital communication remain sealed and untamperable through modern cryptographic "clay":
- **Dynamic Framing**: Obfuscated frame structures that shift based on a rotating salt.
- **Reliable Signaling (FEC)**: Forward Error Correction for critical control messages.
- **Post-Compromise Security**: Continuous entropy injection.

### Compilation Guide

To build the project for multiple platforms, you can use the following commands:

```bash
# Build the native library (including .dll/.so/.a)
cargo build --release

# For cross-compiling (example for Linux on Windows)
# You need the appropriate target installed (e.g., rustup target add x86_64-unknown-linux-gnu)
cargo build --release --target x86_64-unknown-linux-gnu
```

The output will be located in `target/release/` or `target/<target>/release/`.
- Windows: `silent_speaker.dll`, `silent_speaker.lib`
- Linux: `libsilent_speaker.so`, `libsilent_speaker.a`

---

## 中文

**Silent Speaker** 是 **fengni** 协议的高性能、安全性参考实现。它基于 QUIC 构建，旨在抵御流量分析并应对极端不稳定的网络环境。

### fengni (封泥) 协议
**fengni**（英文谐音为 *"funny"*）代表了本系统的核心架构设计。其名称灵感源自中国古代用于信函保密的 **“封泥” (fēng ní)**。

正如古代封泥通过物理印记保护简牍私密性，**fengni** 协议通过现代密码学“数字封泥”确保通信的结构和内容不可观测且不可篡改：
- **动态分帧 (Dynamic Framing)**：基于旋转盐值的混淆帧结构。
- **可靠信令 (FEC)**：针对关键控制消息集成前向纠错。
- **状态自修复**：鲁棒的序列号纠偏机制。
- **多语言支持**：提供生产级 C-API (FFI)，支持 Python, Go, C++ 等多种语言。

### 编译指南

如需在多平台编译该项目，请参考以下指令：

```bash
# 编译原生库（包含 .dll/.so/.a）
cargo build --release

# 交叉编译示例（在 Windows 上编译 Linux 版本）
# 需要先安装对应的 target (例如: rustup target add x86_64-unknown-linux-gnu)
cargo build --release --target x86_64-unknown-linux-gnu
```

编译产物将位于 `target/release/` 或 `target/<target>/release/` 目录下：
- Windows: `silent_speaker.dll`, `silent_speaker.lib`
- Linux: `libsilent_speaker.so`, `libsilent_speaker.a`

---

### License
This project is licensed under the [BSD 3-Clause License](LICENSE).

**Developed with Passion by Feng Ni and the Silent Speaker Contributors.**
