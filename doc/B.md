# B：认证、通道和 SFTP

开发分支 `dev/app` 已包含 A 的传输层提交 `ec79bc8`。

- PT4 已实现密码认证、banner、会话内三次尝试上限和终端密码输入。认证成功时输出 `SSH_MSG_USERAUTH_SUCCESS`。
- PT5 已实现单通道打开、SFTP 子系统请求、双向窗口、跨 SSH 包读写以及 EOF 和关闭。开通道时输出两端编号、初始窗口和最大包长。
- PT6 已实现 SFTP v3 初始化和普通文件的打开、读、写、关闭。客户端仅在文件传输和关闭均成功后报告成功。

## 构建与联调

在 WSL Ubuntu 上使用 GCC 13.3.0、OpenSSL 3.0.13 和 Paramiko 3.5.1 完成构建与联调。`git diff --check` 通过。构建保留既有日志宏格式和 OpenSSL 3 弃用警告。

- 用真实客户端运行 `test/roundtrip.sh`。同一会话上传、下载 `client.c`，`cmp` 通过。
- 空文件和 400,123 字节文件往返的字节比较通过。大文件传输观察到双向窗口调整，服务端初始窗口为 32,768 字节、最大通道包长为 4,096 字节。
- 先错两次再输正确密码可登录。输错三次、超过 99 字节、在密码提示时输入 EOF、请求不存在的文件，以及服务端拒绝打开通道或拒绝子系统时，客户端返回失败。密码输入被中断时，客户端恢复终端回显。
- ASan 和 UBSan 联调通过。检查中修复了 `ssh_get_known_hosts()` 的路径字符串泄漏。

## 手动取证

在 WSL 打开三个终端，均进入仓库根目录。先在终端一构建并启动服务端。现有构建和虚拟环境可直接复用。端口检查无输出时继续。

```sh
cmake -S . -B build -DCMAKE_C_FLAGS="-DLINUX -DLOG_LEVEL=DEBUG"
cmake --build build
python3 -m venv --system-site-packages build/paramiko-venv
build/paramiko-venv/bin/python -m pip install 'paramiko==3.5.1'
ss -ltnH 'sport = :22'
sudo -- "$PWD/build/paramiko-venv/bin/python" -ISB "$PWD/test/paramiko_server.py"
```

服务端绑定 `127.0.0.1:22` 后切回你的普通用户。出现 `Set a temporary lab password:` 时设置一个仅用于这次实验的密码。看到 `Listening on 127.0.0.1:22 as lab` 后保持终端一运行。

在终端二开始抓包。等到 `listening on lo` 再连接客户端。

```sh
sudo tcpdump -i lo -s 0 -U -w - 'host 127.0.0.1 and tcp port 22' > build/roundtrip.pcap
```

在终端三运行客户端和终端记录。

```sh
mkdir -p checkpoint
script -q -e -c 'sh test/roundtrip.sh lab@127.0.0.1' checkpoint/session.typescript
```

输入实验密码，按提示依次执行 `put send/client.c`、`get client.c`、`bye`。看到 `cmp send/client.c client.c succeeded: files are identical.` 后，在终端二按 Ctrl+C 停止抓包，再到终端一按 Ctrl+C 停止服务端。

在 Wireshark 打开 `build/roundtrip.pcap`，使用 `tcp.stream eq 0 && tcp.len > 0` 筛选，若流号不同就替换为本次连接的流号。找到双方的 `New Keys`，再选中随后两个方向各自第一个有载荷的帧。当前环境中的 SSH 分析器会显示方向，但 Info 栏可能没有报文类型。展开 TCP 载荷或选中 SSH 数据显示底部十六进制字节，再保存截图和帧号到 `checkpoint/`。回环两端的 IP 相同，可用 TCP 端口 22 区分服务端方向。可以把首批密文帧与终端日志中的 `type=5`、`type=6` 对照，说明它们承载的是服务请求和确认。下面的命令列出帧号、方向和 TCP 载荷长度。

```sh
tshark -r build/roundtrip.pcap \
  -Y 'tcp.stream eq 0 && tcp.len > 0' -T fields \
  -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.len -e _ws.col.Info
```

| 检查点 | 在材料中定位 |
|---|---|
| CP1 | `server identification:` 所在行。 |
| CP2 | `negotiated KEX=` 所在行。 |
| CP3 | Wireshark 截图中的两个 `New Keys` 和随后的双向密文帧。 |
| CP4 | `SSH_MSG_USERAUTH_SUCCESS` 所在行。 |
| CP5 | `channel opened`、`SFTP subsystem request succeeded` 所在行。 |
| CP6 | 上传、下载及 `cmp` 成功的记录。 |

正式提交使用这次手动会话的实际证据。材料齐全后再整理 `checkpoint/` 的说明、`not-implemented.pdf` 和评分 ZIP。
