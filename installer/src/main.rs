use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

const PAYLOAD_BYTES: &[u8] =
    include_bytes!("../../target/i686-pc-windows-msvc/release/payload.dll");

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    loop {
        print!("\x1B[2J\x1B[1;1H");

        println!("==========================================");
        println!("   QQMusic ID Injector v{VERSION}");
        println!("   GitHub: https://github.com/apoint123/QQMusic-ID-Injector");
        println!("==========================================");
        println!();

        if let Some(path) = find_qq_music_path() {
            println!("检测到的 QQ 音乐安装路径: {}", path.display());
        } else {
            println!("⚠️ 找不到 QQ 音乐安装路径");
        }

        println!();
        println!("请选择操作:");
        println!("  [1] 安装 / 更新插件");
        println!("  [2] 卸载插件");
        println!("  [3] 退出");
        println!();
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => {
                match get_valid_qq_path() {
                    Ok(path) => {
                        if let Err(e) = install_plugin(&path) {
                            println!("\n❌ 安装失败: {e:#}");
                        }
                    }
                    Err(e) => println!("\n❌ 操作取消: {e:#}"),
                }
                pause();
            }
            "2" => {
                match get_valid_qq_path() {
                    Ok(path) => {
                        uninstall_plugin(&path);
                    }
                    Err(e) => println!("\n❌ 操作取消: {e:#}"),
                }
                pause();
            }
            "3" => break,
            _ => {}
        }
    }

    Ok(())
}

fn get_valid_qq_path() -> Result<PathBuf> {
    if let Some(path) = find_qq_music_path() {
        return Ok(path);
    }

    println!("请手动输入 QQ 音乐的安装路径 (包含 QQMusic.exe 的文件夹)");
    println!("也可以直接将文件夹拖入此窗口");

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let path_str = trimmed.trim_matches('"').trim_matches('\'');
        let mut path = PathBuf::from(path_str);

        if path.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("QQMusic.exe"))
            && let Some(parent) = path.parent()
        {
            path = parent.to_path_buf();
        }

        if path.join("QQMusic.exe").exists() {
            return Ok(path);
        }
        println!("❌ 路径无效: 在该路径下未找到 QQMusic.exe，请重新输入。");
    }
}

fn install_plugin(qq_path: &Path) -> Result<()> {
    let target_dll = qq_path.join("msimg32.dll");

    println!("正在写入插件...");
    std::fs::write(&target_dll, PAYLOAD_BYTES)
        .with_context(|| format!("无法写入目标 DLL 文件: {}", target_dll.display()))?;

    println!("安装成功！请重新启动 QQ 音乐以生效");
    Ok(())
}

fn uninstall_plugin(qq_path: &Path) {
    let files_to_remove = ["msimg32.dll"];
    for file_name in files_to_remove {
        let file_path = qq_path.join(file_name);
        if file_path.exists() {
            match std::fs::remove_file(&file_path) {
                Ok(()) => println!("删除: {}", file_path.display()),
                Err(e) => println!("无法删除 {file_name} (QQ 音乐可能正在运行?): {e}"),
            }
        }
    }

    let temp_dir = std::env::temp_dir();
    let logs_dir = temp_dir.join("QQMusicInjectorLogs");
    if logs_dir.exists() {
        match std::fs::remove_dir_all(&logs_dir) {
            Ok(()) => println!("删除: {}", logs_dir.display()),
            Err(e) => println!("无法删除日志目录: {e}"),
        }
    }

    if let Ok(entries) = std::fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with("_msimg32_qq")
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"))
            {
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        println!("删除: {}", path.display());
                    }
                    Err(e) => {
                        eprintln!("删除临时 DLL {} 失败: {e}", path.display());
                    }
                }
            }
        }
    }

    println!("卸载完成");
}

fn pause() {
    println!("\n按任意键继续...");
    let _ = std::io::stdin().read_line(&mut String::new());
}

fn find_qq_music_path() -> Option<PathBuf> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let paths_to_check = [
        "SOFTWARE\\WOW6432Node\\Tencent\\QQMusic",
        "SOFTWARE\\Tencent\\QQMusic",
    ];

    for path in paths_to_check {
        if let Ok(key) = hklm.open_subkey(path)
            && let Ok(install_path) = key.get_value::<String, _>("Install")
        {
            return Some(PathBuf::from(install_path));
        }
    }

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey("Software\\Tencent\\QQMusic")
        && let Ok(install_path) = key.get_value::<String, _>("Install")
    {
        return Some(PathBuf::from(install_path));
    }

    None
}
