//! 命令行入口。
//!
//! 子命令：`service` / `console` / `setup` / `status` / `config sign|import` /
//! `wfp-purge` / `help`。

use std::ffi::c_void;
use std::io;
use std::path::PathBuf;
use std::ptr;

use netguard_core::bootstrap::{self, PreSeed};
use netguard_core::totp;
use netguard_core::{Config, Factors};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    HANDLE, FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_LAYER_NOT_FOUND, FWP_E_NEVER_MATCH,
    FWP_E_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

use crate::store::{Load, Store};

const HELP: &str = "\
NetGuard 应用级网络访问控制

用法：
  netguard.exe service                 以服务方式运行（由服务控制管理器启动）
  netguard.exe console                 在控制台运行，便于调试
  netguard.exe setup --preseed <文件>  从预置配置完成初始化
  netguard.exe status                  输出当前配置状态
  netguard.exe config sign --file <文件> [--write-mac <文件>]
  netguard.exe config import --file <文件>
  netguard.exe wfp-purge               删除本程序残留的 WFP 持久化过滤器 / 子层 / Provider
  netguard.exe help

参数：
  --preseed <文件>     预置配置（JSON）
  --recovery-out <文件> 恢复码输出路径
  --quiet              不输出恢复码
";

fn parse_flag(args: &[String], name: &str) -> Option<String> {
    let position = args.iter().position(|arg| arg == name)?;
    args.get(position + 1).cloned()
}

/// 分派命令行。
pub fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|value| value.as_str()) {
        Some("service") => crate::svc::run_service(),
        Some("console") => crate::svc::run_console(),
        Some("setup") => setup(&args[1..]),
        Some("status") => status(),
        Some("config") => config_command(&args[1..]),
        Some("wfp-purge") => wfp_purge(),
        Some("help") | Some("--help") | Some("-h") | None => {
            print!("{HELP}");
            Ok(())
        }
        Some(other) => {
            eprintln!("未知子命令：{other}");
            print!("{HELP}");
            Err(io::Error::new(io::ErrorKind::InvalidInput, "未知子命令"))
        }
    }
}

fn setup(args: &[String]) -> io::Result<()> {
    let preseed_path = parse_flag(args, "--preseed")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少 --preseed 参数"))?;
    let text = std::fs::read_to_string(&preseed_path)?;
    let preseed = PreSeed::from_json(&text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let bootstrap = bootstrap::build(&preseed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let store = Store::open_default();
    store.save(&bootstrap.config)?;

    if let Some(path) = parse_flag(args, "--recovery-out") {
        std::fs::write(&path, bootstrap::recovery_text(&bootstrap.recovery_codes))?;
    }
    if !args.iter().any(|arg| arg == "--quiet") {
        if let Some(secret) = &bootstrap.totp_secret {
            let url = totp::otpauth_url(secret, "NetGuard", "NetGuard");
            println!("动态口令密钥：{secret}");
            println!("动态口令链接：{url}");
        }
        if !bootstrap.recovery_codes.is_empty() {
            println!("恢复码（仅显示一次）：");
            for code in &bootstrap.recovery_codes {
                println!("  {code}");
            }
        }
        println!("配置已写入 {}", store.paths().dir().display());
    }
    Ok(())
}

fn status() -> io::Result<()> {
    let store = Store::open_default();
    match store.load() {
        Load::Ok(config) => {
            println!("配置：有效");
            println!("总开关：{}", if config.enabled { "启用" } else { "停用" });
            println!("认证方式：{}", config.auth.factors.as_str());
            println!("受控程序：{} 个", config.apps.len());
            println!("拦截散列：{} 个", config.hashes.len());
            for app in &config.apps {
                println!("  - {} => {}", app.name, app.path);
            }
        }
        Load::Absent => println!("配置：未初始化"),
        Load::Tampered(reason) => {
            println!("配置：不可信（{reason}）");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn config_command(args: &[String]) -> io::Result<()> {
    match args.first().map(|value| value.as_str()) {
        Some("sign") => {
            let file = parse_flag(args, "--file")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少 --file 参数"))?;
            let bytes = std::fs::read(&file)?;
            let store = Store::open_default();
            let signature = store.sign_text(&bytes)?;
            match parse_flag(args, "--write-mac") {
                Some(path) => std::fs::write(path, &signature)?,
                None => print!("{signature}"),
            }
            Ok(())
        }
        Some("import") => {
            let file = parse_flag(args, "--file")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少 --file 参数"))?;
            let bytes = std::fs::read(&file)?;
            let config: Config = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let store = Store::open_default();
            store.save(&config)?;
            println!("已导入并重新签名：{}", store.paths().config().display());
            Ok(())
        }
        _ => {
            eprintln!("用法：netguard.exe config sign|import --file <文件>");
            Err(io::Error::new(io::ErrorKind::InvalidInput, "未知 config 子命令"))
        }
    }
}

/// 供后续模块使用的占位，避免未使用导入告警。
#[allow(dead_code)]
fn _factors_name(factors: &Factors) -> &'static str {
    factors.as_str()
}

// ---------------------------------------------------------------- WFP 清理

/// `RPC_C_AUTHN_WINNT`。`crate::wfp` 里的同名常量未导出，此处取同一数值
/// （权威定义在 `Win32::System::Rpc`，与 `wfp.rs` 打开引擎的写法一致）。
const AUTHN_WINNT: u32 = 10;
const ERROR_SUCCESS: u32 = 0;
/// 每次向 WFP 申请的枚举条目上限；返回条数小于该值即表示已到末尾。
const ENUM_BATCH: u32 = 32;

/// NetGuard 只在这两个层上创建过滤器（见 `crate::wfp` 的 `add_one`），因此按层枚举即覆盖
/// 全部历史与当前对象。这里不把 `layerKey` 留成零 GUID —— 零 GUID 的语义文档未定义。
const PURGE_LAYERS: [GUID; 2] = [
    wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
];

/// 把 WFP 返回的 `UINT32` 错误码转成 `io::Error`。
fn wfp_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// 判定「对象不存在」这一类错误。
///
/// 卸载是幂等操作：过滤器、子层、Provider 任意一个缺失都算清理成功。注意
/// `FWP_E_FILTER_NOT_FOUND` 等是 HRESULT 形态（高位为 1 的负数），不能按 Win32 的
/// `ERROR_NOT_FOUND`（1168）比较。
fn wfp_missing(code: u32) -> bool {
    let signed = code as i32;
    signed == FWP_E_FILTER_NOT_FOUND
        || signed == FWP_E_NOT_FOUND
        || signed == FWP_E_SUBLAYER_NOT_FOUND
        || signed == FWP_E_PROVIDER_NOT_FOUND
}

/// WFP 引擎句柄的 RAII 包装：任何返回路径都会执行 `FwpmEngineClose0`。
///
/// 为什么不用 `crate::wfp::Engine`：它的句柄字段是私有的，也没有暴露原始句柄的访问器，
/// 而本命令需要直接调 `Fwpm*Delete*` / 枚举接口。`wfp.rs` 由其它改动负责维护，这里不擅自
/// 加接口，只复制它打开引擎的那几行（同样的 `FWPM_SESSION0` 与 `RPC_C_AUTHN_WINNT`）。
struct PurgeEngine(HANDLE);

impl PurgeEngine {
    fn open() -> io::Result<PurgeEngine> {
        unsafe {
            let mut session: wfp::FWPM_SESSION0 = std::mem::zeroed();
            // 普通（非动态）会话：不改变持久化语义，删除持久化对象也不受影响。
            session.flags = 0;
            let mut handle: HANDLE = std::mem::zeroed();
            let code = wfp::FwpmEngineOpen0(
                ptr::null(),
                AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            );
            if code != ERROR_SUCCESS {
                return Err(wfp_error(code));
            }
            if handle.is_null() {
                return Err(io::Error::other("WFP 引擎句柄为空"));
            }
            Ok(PurgeEngine(handle))
        }
    }
}

impl Drop for PurgeEngine {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                wfp::FwpmEngineClose0(self.0);
            }
        }
    }
}

/// 枚举某一层上属于本程序 Provider 的全部过滤器标识。
///
/// 枚举缓冲区 `entries` 由 WFP 分配、调用方 `FwpmFreeMemory0` 释放；缓冲区存活期间删除
/// 过滤器会让条目内容失效，所以这里只收集标识，删除交给调用方在释放后逐条进行。
unsafe fn collect_layer_filter_ids(engine: HANDLE, layer: GUID) -> io::Result<Vec<u64>> {
    let mut template: wfp::FWPM_FILTER_ENUM_TEMPLATE0 = std::mem::zeroed();
    let mut provider_key = crate::wfp::PROVIDER_KEY;
    template.providerKey = &mut provider_key as *mut _;
    template.layerKey = layer;
    // 0 == FWP_FILTER_ENUM_FULLY_CONTAINED；numFilterConditions 为 0 表示「层内全部过滤器」。
    template.enumType = wfp::FWP_FILTER_ENUM_FULLY_CONTAINED;
    template.numFilterConditions = 0;
    template.filterCondition = ptr::null_mut();
    // MSDN（FWPM_FILTER_ENUM_TEMPLATE0 / actionMask）：只有动作类型与掩码按位与非零的过滤器
    // 才会被返回，0xFFFFFFFF 表示「忽略动作类型」。留 0 会一条也枚举不到，那正是 `wfp.rs`
    // 旧实现「每次启动都再补一对」的根因；也不要只写 FWP_ACTION_FLAG_CALLOUT ——
    // 该标志要求 calloutKey 非空，而这里 calloutKey 是空指针。
    template.actionMask = u32::MAX;
    template.calloutKey = ptr::null_mut();

    let mut enum_handle: HANDLE = std::mem::zeroed();
    let code = wfp::FwpmFilterCreateEnumHandle0(engine, &template, &mut enum_handle);
    if code != ERROR_SUCCESS {
        // 该层一条过滤器都没有（或该层在本机不可用）时没有可清理的对象，属正常情况。
        if wfp_missing(code)
            || code as i32 == FWP_E_NEVER_MATCH
            || code as i32 == FWP_E_LAYER_NOT_FOUND
        {
            return Ok(Vec::new());
        }
        return Err(wfp_error(code));
    }
    if enum_handle.is_null() {
        return Ok(Vec::new());
    }

    let mut ids: Vec<u64> = Vec::new();
    let mut failure: Option<io::Error> = None;
    loop {
        let mut entries: *mut *mut wfp::FWPM_FILTER0 = ptr::null_mut();
        let mut returned: u32 = 0;
        let code = wfp::FwpmFilterEnum0(
            engine,
            enum_handle,
            ENUM_BATCH,
            &mut entries,
            &mut returned,
        );
        let success = code == ERROR_SUCCESS;
        if success && !entries.is_null() {
            for index in 0..returned as usize {
                let entry = *entries.add(index);
                if entry.is_null() {
                    continue;
                }
                ids.push((*entry).filterId);
            }
        }
        if !entries.is_null() {
            wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
        }
        if !success {
            // 枚举到末尾时 WFP 用「找不到」表达，属正常结束；其它错误必须上报。
            if !wfp_missing(code) && code as i32 != FWP_E_NEVER_MATCH {
                failure = Some(wfp_error(code));
            }
            break;
        }
        if returned < ENUM_BATCH {
            break;
        }
    }

    wfp::FwpmFilterDestroyEnumHandle0(engine, enum_handle);
    match failure {
        Some(err) => Err(err),
        None => Ok(ids),
    }
}

/// 按本程序的 Provider 键枚举全部过滤器的标识（逐层，去重）。
unsafe fn collect_filter_ids(engine: HANDLE) -> io::Result<Vec<u64>> {
    let mut ids: Vec<u64> = Vec::new();
    for layer in PURGE_LAYERS {
        ids.extend(collect_layer_filter_ids(engine, layer)?);
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// 逐条删除过滤器标识；已被删除视为成功。返回（计为已清理的条数, 首个失败）。
unsafe fn delete_filters(engine: HANDLE, ids: &[u64]) -> (usize, Option<io::Error>) {
    let mut removed = 0usize;
    let mut failure: Option<io::Error> = None;
    for id in ids {
        let code = wfp::FwpmFilterDeleteById0(engine, *id);
        if code == ERROR_SUCCESS || wfp_missing(code) {
            removed += 1;
        } else if failure.is_none() {
            failure = Some(wfp_error(code));
        }
    }
    (removed, failure)
}

/// 过滤器全部删除后，按「子层 → Provider」清理。
///
/// 两者被过滤器引用时删不掉（`FWP_E_IN_USE`，0x8032000A），所以必须排在过滤器之后。
/// 删不掉时**绝不能当成功**：那意味着仍有过滤器在内核里生效、卸载后照样阻断流量，
/// 因此这里打印警告并返回错误，由 `wfp_purge` 转成非零退出码（`install.ps1` 会据此
/// 走警告路径，但不中断卸载）。旧版本留下的非持久化同名对象也可以用同样的方式清掉。
unsafe fn delete_provider_objects(engine: HANDLE) -> Option<io::Error> {
    let mut failure: Option<io::Error> = None;

    let sublayer_key = crate::wfp::SUBLAYER_KEY;
    let code = wfp::FwpmSubLayerDeleteByKey0(engine, &sublayer_key);
    if code != ERROR_SUCCESS && !wfp_missing(code) {
        warn_delete_object("子层", code);
        failure = Some(wfp_error(code));
    }

    let provider_key = crate::wfp::PROVIDER_KEY;
    let code = wfp::FwpmProviderDeleteByKey0(engine, &provider_key);
    if code != ERROR_SUCCESS && !wfp_missing(code) && failure.is_none() {
        warn_delete_object("Provider", code);
        failure = Some(wfp_error(code));
    }
    failure
}

/// 打印「子层 / Provider 删除失败」的警告。
///
/// `FWP_E_IN_USE` 表示对象仍被过滤器（或其它会话）引用，最可能是上一步还有过滤器没删掉；
/// 这里必须说清后果，避免用户以为卸载已把规则清干净。
fn warn_delete_object(what: &str, code: u32) {
    if code as i32 == FWP_E_IN_USE {
        eprintln!("警告：{what}仍被过滤器引用（FWP_E_IN_USE，0x{code:08X}），存在未能删除的过滤器。");
    } else {
        eprintln!("警告：删除{what}失败（错误码 0x{code:08X}）。");
    }
}

/// `wfp-purge`：删除本程序创建的全部 WFP 对象（过滤器 → 子层 → Provider）。
///
/// 为什么要单列一条命令：过滤器带 `FWPM_FILTER_FLAG_PERSISTENT`，服务进程与二进制都删掉
/// 之后它们仍留在内核里继续阻断流量；重装时还会与旧对象同名冲突（早期版本残留的非持久化
/// Provider / 子层曾触发 `FWP_E_LIFETIME_MISMATCH`）。
///
/// 调用前提：服务必须已经停止 —— 运行中的服务会立刻 reconcile 把过滤器重建回来。
fn wfp_purge() -> io::Result<()> {
    let engine = PurgeEngine::open()?;
    let ids = unsafe { collect_filter_ids(engine.0)? };
    let (removed, filter_failure) = unsafe { delete_filters(engine.0, &ids) };
    let tail_failure = unsafe { delete_provider_objects(engine.0) };
    // engine 在此处离开作用域，由 Drop 执行 FwpmEngineClose0。
    if filter_failure.is_some() || tail_failure.is_some() {
        // 有对象删不掉：退出码非零，让 install.ps1 打出警告（但不中断卸载）。
        eprintln!("警告：已清理过滤器 {removed} 条，但仍有 WFP 对象残留。");
        let err = filter_failure
            .or(tail_failure)
            .unwrap_or_else(|| io::Error::other("WFP 清理未完成"));
        return Err(err);
    }
    println!("已清理过滤器 {removed} 条，子层与 Provider 已清理");
    Ok(())
}

/// 命令行客户端入口。
pub fn client() -> io::Result<()> {
    crate::cli_client::client()
}

/// 预置配置的默认路径（安装器未指定时使用）。
#[allow(dead_code)]
pub fn default_preseed_path() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\NetGuard\preseed.json")
}
