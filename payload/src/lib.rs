use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{panic, thread};

use minhook::MinHook;
use tracing::{debug, error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

use windows::{
    Media::{MusicDisplayProperties, SystemMediaTransportControls},
    Win32::{
        Foundation::{E_FAIL, FALSE, HINSTANCE, HWND, LPARAM, MAX_PATH, TRUE},
        Graphics::Gdi::{BLENDFUNCTION, HDC},
        Storage::FileSystem::{
            CopyFileW, GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO,
            VerQueryValueW,
        },
        System::{
            LibraryLoader::{
                DisableThreadLibraryCalls, GetModuleFileNameW, GetModuleHandleW, GetProcAddress,
                LoadLibraryW,
            },
            Memory::{
                MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, VirtualQuery,
            },
            SystemInformation::GetSystemDirectoryW,
            SystemServices::DLL_PROCESS_ATTACH,
            Threading::GetCurrentProcessId,
            WinRT::{ISystemMediaTransportControlsInterop, RO_INIT_MULTITHREADED, RoInitialize},
        },
        UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible},
    },
    core::{BOOL, Error, HRESULT, HSTRING, IInspectable, Interface, PCSTR, Result, factory, w},
};

static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

fn init_logging() {
    let temp_dir = std::env::temp_dir().join("QQMusicInjectorLogs");

    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("payload")
        .filename_suffix("log")
        .max_log_files(7)
        .build(temp_dir)
        .expect("初始化日志失败");

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_file(true)
        .with_line_number(true)
        .init();

    let _ = LOG_GUARD.set(guard);
}

fn safe_call<F, T>(fallback: T, func: F) -> T
where
    F: FnOnce() -> T + panic::UnwindSafe,
{
    match panic::catch_unwind(func) {
        Ok(result) => result,
        Err(e) => {
            let message = e.downcast_ref::<&'static str>().map_or_else(
                || {
                    e.downcast_ref::<String>()
                        .map_or("未知类型的 Panic", |s| s.as_str())
                },
                |s| *s,
            );
            error!("一个 FFI 调用发生了 Panic: {message}");

            fallback
        }
    }
}

// https://github.com/Kxnrl/NetEase-Cloud-Music-DiscordRPC/blob/d3b77c679379aff1294cc83a285ad4f695376ad6/Vanessa/Players/Tencent.cs
/*
    版本 20.43 ~ 21.93 结构
    struct CurrentSongInfo {
        std::string m_szSong;              // 0x0
        std::string m_szArtist;            // 0x18
        std::string m_szAlbum;             // 0x30
        std::string m_szAlbumThumbnailUrl; // 0x48
        uint32_t m_nSongId;                // 0x60
        private: char pad_64[0x4]; public:
        uint32_t m_nSongDuration;          // 0x68
        uint32_t m_nSongSchedule;          // 0x6c
        uint32_t m_nPlayStatus;            // 0x70
    }; // Size: 0x74
*/

// 如何更新Pattern:
// 1. 在 QQMusic.dll 里搜字符串 "Tencent Technology (Shenzhen) Company Limited", 并且找到引用的函数（理论上只有一个引用）
// 2. 引用到字符串的是一个初始化的函数，在引用到字符串的地方往上找类似这样的伪代码，理论上来讲这个伪代码会重复3次
// byte_xxxxx = 0;
// dword_xxxxx+0x10 = 0;
// dword_xxxxx+0x14 = 15;
// 这个是初始化 std::string, 我们要找的是第一个，这个是当前播放的歌的名字
// 3. 选中然后在汇编页面生成Pattern
const PATTERN: &str =
    "A2 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A2 ?? ?? ?? ?? A3";

#[repr(C)]
#[derive(Copy, Clone)]
union StringData {
    buf: [u8; 16],
    ptr: *const u8,
}

#[repr(C)]
pub struct MsStdString {
    data: StringData,
    len: usize,
    cap: usize,
}

impl std::fmt::Debug for MsStdString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_string_lossy())
    }
}

impl MsStdString {
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        unsafe {
            // 短字符串 (SSO) 优化
            let bytes = if self.cap < 16 {
                if self.len > 16 {
                    return String::from("<无效的字符串>");
                }
                &self.data.buf[..self.len]
            } else {
                if self.data.ptr.is_null() {
                    return String::from("<空指针>");
                }
                std::slice::from_raw_parts(self.data.ptr, self.len)
            };
            String::from_utf8_lossy(bytes).to_string()
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct CurrentSongInfo {
    pub name: MsStdString,                // 0x00
    pub artist: MsStdString,              // 0x18
    pub album: MsStdString,               // 0x30
    pub album_thumbnail_url: MsStdString, // 0x48
    pub id: u32,                          // 0x60
    _pad_64: [u8; 4],                     // 0x64 (padding)
    pub duration: u32,                    // 0x68
    pub schedule: u32,                    // 0x6C
    pub play_status: u32,                 // 0x70
} // Size: 0x74

const _: () = {
    assert!(std::mem::offset_of!(CurrentSongInfo, id) == 0x60);
    assert!(std::mem::size_of::<MsStdString>() == 24);
};

unsafe fn is_target_process() -> bool {
    let mut filename = [0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleFileNameW(None, &mut filename) };

    if len == 0 {
        return false;
    }

    let full_path = String::from_utf16_lossy(&filename[..len as usize]);
    let path = std::path::Path::new(&full_path);

    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("QQMusic.exe"))
}

struct SysFuncs {
    alpha_blend: Option<AlphaBlendFn>,
    transparent_blt: Option<TransparentBltFn>,
    gradient_fill: Option<GradientFillFn>,
}

struct AppState {
    song_struct_addr: AtomicUsize,
    original_update: AtomicPtr<c_void>,
    sys_funcs: OnceLock<SysFuncs>,
}

impl AppState {
    const fn new() -> Self {
        Self {
            song_struct_addr: AtomicUsize::new(0),
            original_update: AtomicPtr::new(std::ptr::null_mut()),
            sys_funcs: OnceLock::new(),
        }
    }

    fn sys(&self) -> &SysFuncs {
        self.sys_funcs.get_or_init(|| unsafe { init_sys_funcs() })
    }
}

static STATE: AppState = AppState::new();

unsafe fn init_sys_funcs() -> SysFuncs {
    // 加载相同模块名时，windows 会返回相同的句柄，导致循环加载相同函数并因栈溢出而崩溃
    // 所以先复制一份到临时目录再加载
    let mut sys_dir_buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut sys_dir_buf)) } as usize;
    if len == 0 {
        error!("无法获取系统目录");
        return SysFuncs {
            alpha_blend: None,
            transparent_blt: None,
            gradient_fill: None,
        };
    }
    let sys_dir = String::from_utf16_lossy(&sys_dir_buf[..len]);

    let source_path = format!("{sys_dir}\\msimg32.dll");

    let pid = unsafe { GetCurrentProcessId() };
    let temp_dir = std::env::temp_dir();

    if let Ok(entries) = std::fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with("_msimg32_qq_")
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"))
            {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(path = ?path, "清理旧的临时 DLL 失败: {e}");
                } else {
                    debug!(path = ?path, "已清理旧的临时 DLL");
                }
            }
        }
    }

    let dest_path_buf = temp_dir.join(format!("_msimg32_qq_{pid}.dll"));
    let dest_path = dest_path_buf.to_string_lossy().to_string();

    let source_h = HSTRING::from(&source_path);
    let dest_h = HSTRING::from(&dest_path);

    if let Err(e) = unsafe { CopyFileW(&source_h, &dest_h, false) } {
        error!("复制系统 msimg32 失败: {e:?}");
    }

    let lib = match unsafe { LoadLibraryW(&dest_h) } {
        Ok(h) => h,
        Err(e) => {
            error!("无法加载系统 msimg32 副本: {e}");
            return SysFuncs {
                alpha_blend: None,
                transparent_blt: None,
                gradient_fill: None,
            };
        }
    };

    info!(path = %dest_path, "正在加载代理 DLL");

    let get_func = |name: &str| -> Option<usize> {
        let name_h = std::ffi::CString::new(name).ok()?;
        let addr = unsafe { GetProcAddress(lib, PCSTR(name_h.as_ptr().cast::<u8>())) };
        addr.map(|f| f as usize)
    };
    unsafe {
        SysFuncs {
            alpha_blend: get_func("AlphaBlend").map(|f| std::mem::transmute(f)),
            transparent_blt: get_func("TransparentBlt").map(|f| std::mem::transmute(f)),
            gradient_fill: get_func("GradientFill").map(|f| std::mem::transmute(f)),
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(
    hinstance: HINSTANCE,
    reason: u32,
    _reserved: *const c_void,
) -> BOOL {
    safe_call(FALSE, || {
        if reason == DLL_PROCESS_ATTACH {
            unsafe {
                let _ = DisableThreadLibraryCalls(hinstance.into());
            };

            if unsafe { is_target_process() } {
                init_logging();
                thread::spawn(|| unsafe { main_thread() });
            }
        }
        TRUE
    })
}

unsafe fn main_thread() {
    unsafe {
        info!("Hook 已加载，等待初始化...");
        log_host_version();

        let _ = RoInitialize(RO_INIT_MULTITHREADED);

        thread::spawn(|| scan_for_address());

        if let Err(e) = install_hook() {
            error!("Hook 安装失败: {e:?}");
        }
    }
}

unsafe fn find_main_window() -> HWND {
    unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let current_pid = unsafe { GetCurrentProcessId() };
        let mut window_pid = 0;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&raw mut window_pid)) };

        if window_pid == current_pid && unsafe { IsWindowVisible(hwnd).as_bool() } {
            let target_ptr = lparam.0 as *mut HWND;
            if target_ptr.is_null() {
                error!("target_ptr 指针为空");
            } else {
                unsafe { *target_ptr = hwnd };
            }
            return FALSE;
        }
        TRUE
    }

    let current_pid = unsafe { GetCurrentProcessId() };
    let start_time = Instant::now();
    let timeout = Duration::from_secs(15);

    info!(pid = current_pid, "开始查找主窗口");

    loop {
        let mut found_hwnd = HWND(std::ptr::null_mut());

        let _ =
            unsafe { EnumWindows(Some(enum_window_proc), LPARAM(&raw mut found_hwnd as isize)) };

        if !found_hwnd.0.is_null() {
            info!(hwnd = ?found_hwnd, "找到主窗口句柄");
            return found_hwnd;
        }

        if start_time.elapsed() > timeout {
            warn!("查找主窗口超时，初始化可能会失败");
            return HWND(std::ptr::null_mut());
        }

        thread::sleep(Duration::from_millis(500));
    }
}

unsafe fn install_hook() -> Result<()> {
    let interop: ISystemMediaTransportControlsInterop =
        factory::<SystemMediaTransportControls, ISystemMediaTransportControlsInterop>()?;
    let hwnd = unsafe { find_main_window() };
    let smtc: SystemMediaTransportControls = unsafe { interop.GetForWindow(hwnd) }?;

    let updater = smtc.DisplayUpdater()?;
    let updater_raw: IInspectable = updater.cast()?;
    let raw_ptr = updater_raw.as_raw();

    if raw_ptr.is_null() {
        error!("DisplayUpdater 原始指针为空");
        return Err(Error::from(E_FAIL));
    }

    let vtable_ptr = unsafe { *raw_ptr.cast::<*mut usize>() };
    if vtable_ptr.is_null() {
        error!("DisplayUpdater VTable 指针为空");
        return Err(Error::from(E_FAIL));
    }

    let update_method_addr = unsafe { *vtable_ptr.add(17) } as *mut c_void;

    info!(addr = ?update_method_addr, "获取到 Update 方法地址");

    let target = update_method_addr;
    let detour = detour_update as *mut c_void;

    match unsafe { MinHook::create_hook(target, detour) } {
        Ok(original) => {
            STATE.original_update.store(original, Ordering::Relaxed);
            unsafe { MinHook::enable_hook(target).ok() };
            info!("MinHook 安装成功");
            Ok(())
        }
        Err(e) => {
            error!("MinHook 创建失败: {e:?}");
            Err(Error::from(E_FAIL))
        }
    }
}

unsafe extern "system" fn detour_update(this: *mut c_void) -> HRESULT {
    if this.is_null() {
        return E_FAIL;
    }

    safe_call((), || {
        let _ = (|| -> Result<()> {
            let struct_addr = STATE.song_struct_addr.load(Ordering::Relaxed);

            if struct_addr != 0 {
                let song_info = unsafe { &*(struct_addr as *const CurrentSongInfo) };

                let id = song_info.id;
                let name = song_info.name.to_string_lossy();
                let artist = song_info.artist.to_string_lossy();
                let album = song_info.album.to_string_lossy();

                if let Some(props) = unsafe { get_music_properties_from_vtable(this) } {
                    let genres = props.Genres()?;

                    genres.Clear()?;

                    // 本地音乐的 ID 为 0
                    if id != 0 {
                        let formatted_id = format!("QQ-{id}");
                        genres.Append(&HSTRING::from(&formatted_id))?;
                        info!(
                            song.id = %formatted_id,
                            song.name = %name,
                            song.artist = %artist,
                            song.album = %album,
                            "写入流派字段"
                        );
                    } else {
                        info!(
                            song.id = id,
                            song.name = %name,
                            "ID 为 0, 跳过写入"
                        );
                    }
                } else {
                    warn!("无法从 VTable 获取 MusicDisplayProperties");
                }
            } else {
                info!("内存特征码尚未定位，跳过本次 Update");
            }
            Ok(())
        })();
    });

    safe_call(E_FAIL, || {
        let original_ptr = STATE.original_update.load(Ordering::Relaxed);
        if original_ptr.is_null() {
            E_FAIL
        } else {
            let original: unsafe extern "system" fn(*mut c_void) -> HRESULT =
                unsafe { std::mem::transmute(original_ptr) };
            unsafe { original(this) }
        }
    })
}

unsafe fn get_music_properties_from_vtable(this: *mut c_void) -> Option<MusicDisplayProperties> {
    type MusicPropertiesFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;

    if this.is_null() {
        error!("get_music_properties_from_vtable this 指针为空");
        return None;
    }

    let index = 12; // MusicProperties 索引
    let vtable_ptr_ptr = this.cast::<*mut usize>();

    let vtable = unsafe { *vtable_ptr_ptr };
    if vtable.is_null() {
        error!("Update 对象 VTable 指针为空");
        return None;
    }

    let method_ptr_addr = unsafe { vtable.add(index) };
    let method_ptr = unsafe { *method_ptr_addr } as *mut c_void;

    if method_ptr.is_null() {
        error!(index = index, "VTable 指定索引处的方法指针为空");
        return None;
    }

    let method: MusicPropertiesFn = unsafe { std::mem::transmute(method_ptr) };

    let mut result_ptr: *mut c_void = std::ptr::null_mut();

    match unsafe { method(this, &raw mut result_ptr) }.ok() {
        Ok(()) if !result_ptr.is_null() => {
            Some(unsafe { MusicDisplayProperties::from_raw(result_ptr) })
        }
        Ok(()) => {
            warn!("MusicProperties 方法调用成功 (S_OK)，但返回了空对象");
            None
        }
        Err(e) => {
            warn!("调用 MusicProperties 方法失败: {e}");
            None
        }
    }
}

unsafe fn scan_for_address() {
    let module_handle = unsafe { GetModuleHandleW(w!("QQMusic.dll")) };
    if let Ok(handle) = module_handle {
        let base_addr = handle.0 as usize;

        info!(
            base_addr = format_args!("0x{base_addr:X}"),
            "找到 QQMusic.dll 模块基址"
        );

        let scan_limit = base_addr + 20 * 1024 * 1024;

        info!("开始扫描内存特征码...");
        let pattern_bytes = parse_pattern(PATTERN);

        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(60);

        loop {
            if start_time.elapsed() > timeout {
                warn!(timeout = ?timeout, "扫描超时，未找到特征码，插件功能将不可用");
                break;
            }

            let mut current_addr = base_addr;
            let mut found = false;

            while current_addr < scan_limit {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let query_size = unsafe {
                    VirtualQuery(
                        Some(current_addr as *const c_void),
                        &raw mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };

                if query_size == 0 {
                    break;
                }

                let next_addr = current_addr + mbi.RegionSize;

                let is_committed = mbi.State == MEM_COMMIT;
                let protect = mbi.Protect.0;
                let is_guard = (protect & PAGE_GUARD.0) != 0;

                let base_protect = protect & 0xFF;
                let is_readable = base_protect == PAGE_READONLY.0
                    || base_protect == PAGE_READWRITE.0
                    || base_protect == PAGE_EXECUTE_READ.0
                    || base_protect == PAGE_EXECUTE_READWRITE.0;

                if is_committed && !is_guard && is_readable {
                    let safe_end = next_addr.min(scan_limit);
                    let safe_len = safe_end.saturating_sub(current_addr);

                    if safe_len > 0 {
                        let slice = unsafe {
                            std::slice::from_raw_parts(current_addr as *const u8, safe_len)
                        };

                        if let Some(offset) = find_pattern_bytes(slice, &pattern_bytes) {
                            let pattern_addr = current_addr + offset;
                            let ptr_addr = (pattern_addr + 1) as *const u32;
                            let struct_addr =
                                unsafe { std::ptr::read_unaligned(ptr_addr) } as usize;

                            let duration = start_time.elapsed();
                            info!(
                                duration = ?duration,
                                pattern_addr = format_args!("0x{pattern_addr:X}"),
                                struct_addr = format_args!("0x{struct_addr:X}"),
                                "特征码定位成功"
                            );

                            STATE.song_struct_addr.store(struct_addr, Ordering::Relaxed);
                            found = true;
                            break;
                        }
                    }
                }

                current_addr = next_addr;
            }

            if found {
                break;
            }

            thread::sleep(std::time::Duration::from_millis(1000));
        }
    } else {
        error!("无法获取 QQMusic.dll 句柄");
    }
}

fn parse_pattern(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .map(|s| {
            if s == "?" || s == "??" {
                None
            } else {
                u8::from_str_radix(s, 16).ok()
            }
        })
        .collect()
}

fn find_pattern_bytes(data: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| {
        w.iter()
            .zip(pattern)
            .all(|(b, p)| p.is_none_or(|x| *b == x))
    })
}

// 调试用
unsafe fn log_host_version() {
    let mut filename = [0u16; MAX_PATH as usize];
    let len =
        unsafe { windows::Win32::System::LibraryLoader::GetModuleFileNameW(None, &mut filename) };
    if len == 0 {
        warn!("无法获取当前进程文件名");
        return;
    }

    let path = windows::core::PCWSTR(filename.as_ptr());
    let size = unsafe { GetFileVersionInfoSizeW(path, None) };
    if size == 0 {
        warn!("无法获取文件版本信息大小");
        return;
    }

    let mut data = vec![0u8; size as usize];

    if unsafe { GetFileVersionInfoW(path, Some(0), size, data.as_mut_ptr().cast()) }.is_ok() {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len: u32 = 0;

        if unsafe { VerQueryValueW(data.as_ptr().cast(), w!("\\"), &raw mut ptr, &raw mut len) }
            .as_bool()
        {
            let info = unsafe { &*(ptr as *const VS_FIXEDFILEINFO) };

            let v1 = (info.dwFileVersionMS >> 16) & 0xFFFF;
            let v2 = info.dwFileVersionMS & 0xFFFF;
            let v3 = (info.dwFileVersionLS >> 16) & 0xFFFF;
            let v4 = info.dwFileVersionLS & 0xFFFF;

            info!(
                version = %format!("{v1}.{v2}.{v3}.{v4}"),
                "找到进程版本"
            );
        } else {
            warn!("无法查询版本值");
        }
    } else {
        warn!("无法读取文件版本信息");
    }
}

type AlphaBlendFn = unsafe extern "system" fn(
    HDC,
    i32,
    i32,
    i32,
    i32,
    HDC,
    i32,
    i32,
    i32,
    i32,
    BLENDFUNCTION,
) -> BOOL;

type TransparentBltFn =
    unsafe extern "system" fn(HDC, i32, i32, i32, i32, HDC, i32, i32, i32, i32, u32) -> BOOL;

// 用 *const c_void 代替指针参数，反正只是透传
type GradientFillFn =
    unsafe extern "system" fn(HDC, *const c_void, u32, *const c_void, u32, u32) -> BOOL;

#[unsafe(no_mangle)]
#[allow(
    clippy::missing_safety_doc,
    reason = "我们不会主动调用这个函数, 不需要文档"
)]
pub unsafe extern "system" fn AlphaBlend(
    hdcdest: HDC,
    xorigin: i32,
    yorigin: i32,
    wdest: i32,
    hdest: i32,
    hdcsrc: HDC,
    xsrc: i32,
    ysrc: i32,
    wsrc: i32,
    hsrc: i32,
    ftn: BLENDFUNCTION,
) -> BOOL {
    safe_call(FALSE, || unsafe {
        STATE.sys().alpha_blend.map_or(FALSE, |func| {
            func(
                hdcdest, xorigin, yorigin, wdest, hdest, hdcsrc, xsrc, ysrc, wsrc, hsrc, ftn,
            )
        })
    })
}

#[unsafe(no_mangle)]
#[allow(
    clippy::missing_safety_doc,
    reason = "我们不会主动调用这个函数, 不需要文档"
)]
pub unsafe extern "system" fn TransparentBlt(
    hdcdest: HDC,
    xorigin: i32,
    yorigin: i32,
    wdest: i32,
    hdest: i32,
    hdcsrc: HDC,
    xsrc: i32,
    ysrc: i32,
    wsrc: i32,
    hsrc: i32,
    crtransparent: u32,
) -> BOOL {
    safe_call(FALSE, || unsafe {
        STATE.sys().transparent_blt.map_or(FALSE, |func| {
            func(
                hdcdest,
                xorigin,
                yorigin,
                wdest,
                hdest,
                hdcsrc,
                xsrc,
                ysrc,
                wsrc,
                hsrc,
                crtransparent,
            )
        })
    })
}

#[unsafe(no_mangle)]
#[allow(
    clippy::missing_safety_doc,
    reason = "我们不会主动调用这个函数, 不需要文档"
)]
pub unsafe extern "system" fn GradientFill(
    hdc: HDC,
    pvertex: *const c_void,
    nvertex: u32,
    pmesh: *const c_void,
    nmesh: u32,
    ulmode: u32,
) -> BOOL {
    safe_call(FALSE, || unsafe {
        STATE.sys().gradient_fill.map_or(FALSE, |func| {
            func(hdc, pvertex, nvertex, pmesh, nmesh, ulmode)
        })
    })
}
