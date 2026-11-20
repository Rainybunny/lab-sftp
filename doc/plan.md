# Mini SFTP 双人实验计划

## 一、公共接口、文件归属与交付

[课程任务与评分](../README.md#assignment)列出 PT1 至 PT6、CP1 至 CP6，共 12 分；本版没有具体 WT 题目。以 README 对应小节的报文字段、顺序及课程约束为准，以已有头文件为 C 接口。两人从含本计划的同一提交建立开发分支。

| 调用边界 | 双方约定 |
|---|---|
| 客户端入口 | 保留 [client.c](../client.c) 的单参数调用：`build/client username@hostname`，默认 TCP 22。客户端创建并持有同一个 `ssh_session`，通过 `ssh_options_set(session, SSH_OPTIONS_HOST, host)` 配置目标。 |
| A 交给 B | [ssh_connect](../src/session.c) 内，`ssh_dh_handshake(session)` 成功后，双向密钥已生效。保留随后对 B 所有的 `int ssh_request_auth(ssh_session session)` 的一次调用；由它发送 `SSH_MSG_SERVICE_REQUEST("ssh-userauth")` 并接收同名 `SSH_MSG_SERVICE_ACCEPT`。因此外部看到 `ssh_connect(session) == SSH_OK` 时服务已获准，可直接认证；失败沿原路径返回 `SSH_ERROR`。 |
| SSH 收发 | [packet.h](../include/libsftp/packet.h)：B 在 `session->out_buffer` 写入一条消息，首字节为类型，然后调用 `int ssh_packet_send(ssh_session session)`；成功后发送缓冲已重置。调用 `int ssh_packet_receive(ssh_session session)` 成功后，从 `session->in_buffer` 读取本包类型和后续字段，并在下次接收前消费所需内容。两函数成功返回 `SSH_OK`，失败返回 `SSH_ERROR`。包长、填充、加解密、序号、MAC 均由 A 的包层处理。 |
| 上层调用 | 保留 [client.c](../client.c) 的调用顺序和 [SFTP API](../include/libsftp/libsftp.h) 的签名：密码认证成功后创建 SFTP 会话并初始化；以现有 `put`、`get`、`bye` 交互。读写的 `count` 单位为字节，返回实际字节数，读到 EOF 返回 0，出错返回负值；打开失败返回 NULL。 |

A 独占第二部分列出的四个源文件，B 独占第三部分列出的三个源文件及测试脚本。沿用现有公共头文件、会话结构、日志和构建目标；本计划无需新增公共函数。开发分支共享 `doc/`、`test/`。A、B 分别在 `doc/A.md`、`doc/B.md` 简记本人任务状态、构建结果和待联调项，最终以实际证据更新完成情况。

云端保留开发分支；另设评分分支，提交课程原项目、完成的实现、根目录 `checkpoint/` 和 `not-implemented.pdf`。评分分支的文件树及由其生成的压缩包均排除 `doc/`、`test/`、本地构建产物和临时测试文件。

## 二、A：传输层与 CP1 至 CP3 的取证准备

1. **PT1，src/session.c。** 按 [Version Exchange](../README.md#version-exchange) 完成接收：保留现有客户端标识及线上 CRLF；跳过服务端标识前的说明行，将实际 SSH 标识去掉行尾存入会话，供交换哈希和 CP1 使用。
2. **PT2，src/kex.c。** 按 [Algorithm Negotiation](../README.md#algorithm-negotiation) 及骨架中的方法数组处理 KEXINIT 的有序名称列表，保存交换哈希所用原始载荷。按客户端优先顺序取共同方法；必选项无交集时失败。仅使用骨架套件：diffie-hellman-group1-sha1、ssh-rsa、双向 aes256-cbc、双向 hmac-sha1、无压缩。CP2 显示本次实际选中值。
3. **PT3，src/dh.c、src/packet.c。** 按 [DH Key Exchange](../README.md#dh-key-exchange)、Encryption、Integrity、Public Key 各节完成 DH 应答处理和 NEWKEYS，复用现有 K、H、会话标识与方向密钥派生逻辑；补全接收端 MAC 校验。按课程约定不增加服务器公钥验证。CP3 使用线上密文取证。
4. 按 [Quick Start](../README.md#quick-start) 独立编译。Linux 在仓库根目录运行 `cmake -B build -DCMAKE_C_FLAGS="-DLINUX -DLOG_LEVEL=DEBUG"`、`cmake --build build`；macOS 使用 README 对应参数。构建结果记入 A 的状态文件。

## 三、B：认证、通道、文件操作与往返测试

1. **PT4，src/auth.c。** 沿用第一部分的服务请求。按 [Authentication Layer](../README.md#2-ssh-authentication-layer) 发送用户名、服务名 `ssh-connection`、方法 `password`、FALSE、密码。显示 banner 后继续等结果；成功返回 `SSH_OK` 并留下 CP4 成功记录；允许重试的错误密码返回 `SSH_AGAIN`，三次失败或不可恢复错误返回 `SSH_ERROR`。
2. **PT5，src/channel.c。** 按 [Connection Layer](../README.md#3-ssh-connection-layer) 打开 `session` 通道，再请求 `subsystem`、要求回复、名称 `sftp`。处理打开确认或失败、子系统成功或失败；确认中保存对端通道号、窗口、最大包长。发往对端用对端编号，收到的 recipient 对应本地编号；CP5 显示双方编号与窗口。完成现有读取循环的缓存消费、窗口调整、数据、EOF、关闭与请求分支，使上层可跨 SSH 数据包读取。
3. **PT6，src/sftp.c。** 按 [SFTP Layer](../README.md#4-sftp-layer) 的 Initialization、File Open/Close、File Read & Write、Server Response 字段表完成现有函数。沿用 v3、请求编号、句柄及文件偏移；OPEN 返回 HANDLE 或错误 STATUS，READ 返回 DATA 或 EOF/错误 STATUS，WRITE/CLOSE 检查 STATUS。沿用客户端打开参数：上传用 `O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU`，下载用 `O_RDONLY, 0`。
4. **test/roundtrip.sh。** 约定从仓库根目录执行 `sh test/roundtrip.sh username@hostname`，使用刚编译的客户端和仓库根目录的 `client.c`。脚本准备临时目录及其下的 `send/client.c` 副本，从临时目录启动客户端，密码由操作者在终端输入。在同一会话依次输入 `put send/client.c`、`get client.c`、`bye`：远端名称为 `client.c`，下载到临时目录的 `client.c`。脚本最后执行 `cmp send/client.c client.c` 并返回比较结果。使用允许覆盖远端同名文件的实验账号。
5. 按第二部分同一命令独立编译，在 B 的状态文件记录结果；本阶段写好脚本，第四部分执行真实往返。

## 四、合并、联调与评分交付

1. 合并两条开发分支，按 Quick Start 重新构建。准备支持课程套件及密码登录的 SFTP 实验服务器、终端记录工具和抓包权限。README 对整个实验的估时为 20 至 30 小时。
2. 连接前启动抓包和终端记录，运行 B 的往返测试。在同一次成功会话中按下表取证。每项在 `checkpoint/` 中配一句说明；共用终端记录时标明对应行或片段，截图标明对应包号。证据不含密码。

   | 检查点 | 评分证据 |
   |---|---|
   | CP1 | 本次连接收到的完整服务端标识字符串。 |
   | CP2 | 实际协商的算法套件。 |
   | CP3 | 同一 TCP 流中，标出双方 NEWKEYS 和切换后传输认证或通道数据的加密报文。 |
   | CP4 | 服务端返回认证成功。 |
   | CP5 | 通道打开成功及两端编号、窗口大小。 |
   | CP6 | 上传和下载源码 `client.c` 的终端记录及 `cmp` 成功结果。 |

3. 按 [Submission](../README.md#submission) 整理评分分支。全部完成则提交空文件 `not-implemented.pdf`；有缺项则如实列出任务与原因。记录最终联调结果后，仅将第一部分规定的交付内容放入评分分支。
4. 从评分分支导出 `lab4-name1-studentID1-name2-studentID2.zip`（替换为两人的姓名和学号），核对归档含完整项目、六项 CP 材料及规定文件，且不含开发目录。从归档解压目录按 README 构建成功后，将该归档按 README 所列邮箱提交。
