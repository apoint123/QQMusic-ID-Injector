# QQMusic-ID-Injector

一个适用于 QQ 音乐客户端的插件，可将 QQ 音乐当前播放的 ID 上传到 SMTC 中。

## 安装

### 自动安装

1. 从 [Releases](https://github.com/apoint123/QQMusic-ID-Injector/releases) 页面下载 `Installer.exe`
2. 右键 `Installer.exe` 并点击 **以管理员身份运行**
3. 关闭 QQ 音乐
4. 按照屏幕上的指示安装插件
5. 启动 QQ 音乐

### 手动安装

1. 从 [Releases](https://github.com/apoint123/QQMusic-ID-Injector/releases) 页面下载 `payload.dll`
2. 重命名 `payload.dll` 为 `msimg32.dll`
3. 将文件移动到 QQ 音乐的安装目录
    * 通常位于 `C:\Program Files (x86)\Tencent\QQMusic`

## 已知问题

* 播放本地歌曲时，无法获取到 ID。

## 构建

### 先决条件

* Rust 工具链

### 构建步骤

    ```bash
    git clone https://github.com/apoint123/QQMusic-ID-Injector.git
    cd QQMusic-ID-Injector
    rustup target add i686-pc-windows-msvc  # 因为 QQ 音乐是 32 位的
    cargo build --package payload --release
    cargo build --package installer --release
    ```

## 免责声明

本软件仅供**教育用途**。

* 本软件与腾讯科技（深圳）有限公司无任何关联，亦未获得其认可或授权。

* 因使用本工具而导致的任何封禁、崩溃或数据丢失，作者概不负责。

## 致谢

* [NetEase-Cloud-Music-DiscordRPC](https://github.com/Kxnrl/NetEase-Cloud-Music-DiscordRPC): 提供了 QQ 音乐的内存信息

## 许可

[MIT](LICENSE)
