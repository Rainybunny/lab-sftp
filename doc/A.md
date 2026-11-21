# A：SSH 传输层

开发分支为 `dev/transport`，基线为 `231ae39`。

- PT1 已完成。客户端发送带 CRLF 的原有标识，逐行跳过服务端前置文本，保存并记录去除行尾的 SSH 标识。
- PT2 已完成。保存双方 KEXINIT 原始载荷，按名称选择必选算法。无共同方法时连接失败。
- PT3 已完成。计算共享密钥、交换哈希和方向密钥，在各自的 NEWKEYS 后启用加密，并验证接收端 HMAC。现有套接字封装处理了提前 EOF 和短写，供版本交换和包层共用。
- A 与 B 的交接已验证。密钥生效后，`ssh_connect` 通过现有 `ssh_request_auth` 收到 `ssh-userauth` 的服务确认并返回 `SSH_OK`。

## 构建

Linux，GCC 11.4.0，OpenSSL 3.0.15。使用 README 的 Linux 编译选项，本机另指定 OpenSSL 的 Conda 安装路径。

```sh
cmake -B build -DCMAKE_C_FLAGS="-DLINUX -DLOG_LEVEL=DEBUG" \
  -DOPENSSL_ROOT_DIR=/home/vullar/miniconda3
cmake --build build
git diff --check
```

配置、编译和差异检查通过。编译仍有既有日志宏的格式警告和 OpenSSL 3 的弃用警告。

## CP1 至 CP3 取证准备

通过 `ssh_connect` 与 Paramiko 3.5.1 服务端在本机回环 TCP 端口完成互通。服务端在 SSH 标识前发送了两行说明，其中第一行超过 255 字节。

- CP1 日志显示完整服务端标识 `SSH-2.0-paramiko_3.5.1 lab transport test`。
- CP2 日志显示密钥交换 `diffie-hellman-group1-sha1`、主机密钥 `ssh-rsa`，双向均为 `aes256-cbc`、`hmac-sha1`、`none`（压缩）。
- CP3 在同一连接的服务端套接字处记录传输字节。客户端方向的明文消息类型依次为 20、30、21，服务端方向为 20、31、21。两端各自的类型 21（NEWKEYS）后，各记录到 32 字节密文及 20 字节 MAC。客户端在包层解析出的对应消息为类型 5（SERVICE_REQUEST）及类型 6（SERVICE_ACCEPT）。

```text
客户端 → 服务端，NEWKEYS 后
2c168125b6f31de62313bc38a54ba7238f42bff895217661442215ce88000e1a a5e1064873a498ea0b3ca552c12eecb9a436381f
服务端 → 客户端，NEWKEYS 后
9a46b4e047b5b821e0a142e329f293024bac6d82c75cda0c1bcc09c23cf1a919 2cb3d23b2f6f996a6d0fb1bd52832624c34e7d27
```

无共同加密算法、服务端在标识前关闭连接、服务确认包 MAC 错误时，`ssh_connect` 均返回 `SSH_ERROR`。

合并后已在 Paramiko 3.5.1 回环服务上复测通过。评分会话的标识、协商结果和 NEWKEYS 记录见 [session.typescript 第 5 至 15 行](../checkpoint/session.typescript)。[抓包截图](../checkpoint/CP3.png)的第 15、16 帧显示双方 NEWKEYS，第 17、18 帧显示随后服务请求和确认的密文。
