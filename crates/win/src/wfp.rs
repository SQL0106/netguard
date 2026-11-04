//! Windows Filtering Platform 封装。
//!
//! 本模块只负责「为用户态进程添加/删除持久化出站阻断过滤器」，以及按 Provider 键
//! 枚举自身过滤器做增量协调（reconcile）。所有过滤器均为 `FWPM_FILTER_FLAG_PERSISTENT`，
//! 因此服务进程退出后拦截依然存在。
//!
//! 设计要点：
//! - 过滤器仅挂 `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`。ICS/NAT 转发流量走 IP 转发层，
//!   不经过 ALE 授权层，因此开启移动热点不受影响。
//! - 每个应用两条过滤器（IPv4 与 IPv6），显示名分别为 `ng4|<路径>` 与 `ng6|<路径>`，
//!   协调时据此还原应拦截集合，不依赖进程内状态。

use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

/// `RPC_C_AUTHN_WINNT`。常量位于 `Win32::System::Rpc`，此处直接取数值以避免额外特性。
const AUTHN_WINNT: u32 = 10;
const ERROR_SUCCESS: u32 = 0;
/// Win32 的「找不到」。
const ERROR_NOT_FOUND: i32 = 1168;
/// `FWP_E_ALREADY_EXISTS`：WFP 对象（Provider / 子层 / 过滤器）已存在。
/// 注意它**不是** Win32 的 `ERROR_ALREADY_EXISTS`（183），
/// 用后者比较会把「已存在」误判成真错误。
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
/// `FWP_E_FILTER_NOT_FOUND`：过滤器不存在；枚举不到对象与重复删除都可视为「没有」。
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
/// `FWP_E_NEVER_MATCH`：枚举模板匹配不到任何对象。
/// 首次运行尚无任何过滤器时 `FwpmFilterCreateEnumHandle0` 返回该码，属正常情况。
const FWP_E_NEVER_MATCH: u32 = 0x8032_0033;

const NAME_V4: &str = "ng4|";
const NAME_V6: &str = "ng6|";
/// 每次 `FwpmFilterEnum0` 请求的最大条数。返回条数小于该值即表示已到末尾。
const ENUM_BATCH: u32 = 32;

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> GUID {
    GUID {
        data1,
        data2,
        data3,
        data4,
    }
}

/// 本程序专用的 Provider 键。
pub const PROVIDER_KEY: GUID = guid(0x7b9e_5c11, 0x0f4a, 0x4d21, [0x9a, 0x61, 0x1c, 0x0b, 0x2e, 0x77, 0x51, 0x01]);
/// 本程序专用的子层键。权重取最大值，确保位于其它子层之前。
pub const SUBLAYER_KEY: GUID = guid(0x7b9e_5c12, 0x0f4a, 0x4d21, [0x9a, 0x61, 0x1c, 0x0b, 0x2e, 0x77, 0x51, 0x02]);

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn is_code(err: &io::Error, code: i32) -> bool {
    err.raw_os_error() == Some(code)
}

/// 一条已存在的过滤器。
#[derive(Debug, Clone)]
pub struct Existing {
    pub path: String,
    pub ipv6: bool,
    pub filter_id: u64,
}

/// 协调结果统计。
#[derive(Debug, Default, Clone, Copy)]
pub struct ReconcileReport {
    pub added: usize,
    pub removed: usize,
    pub kept: usize,
    /// 本次枚举到的既有过滤器条数（去重前）。仅用于日志观测，不参与协调判断。
    pub observed: usize,
}

/// WFP 引擎句柄。
pub struct Engine {
    handle: HANDLE,
}

impl Engine {
    /// 打开引擎。需要管理员或 LocalSystem 权限。
    pub fn open() -> io::Result<Engine> {
        unsafe {
            let mut session: wfp::FWPM_SESSION0 = std::mem::zeroed();
            session.flags = 0;
            let mut handle: HANDLE = std::mem::zeroed();
            let code = wfp::FwpmEngineOpen0(ptr::null(), AUTHN_WINNT, ptr::null(), &session, &mut handle);
            check(code)?;
            Ok(Engine { handle })
        }
    }

    /// 确保 Provider 与子层以「持久化」形态存在。
    ///
    /// 旧版本曾用不带标志的 Provider / 子层，它们会残留下来；持久化过滤器引用这种
    /// 非持久化对象时，`FwpmFilterAdd0` 返回 `FWP_E_LIFETIME_MISMATCH`（0x80320016），
    /// 且无法事后补救。所以这里先尝试删除同名对象再重建：删除失败（不存在、或仍被
    /// 现有过滤器引用）一律忽略，随后的「已存在」也视为成功。
    pub fn ensure_provider_sublayer(&self) -> io::Result<()> {
        unsafe {
            let sub_key = SUBLAYER_KEY;
            let prov_key = PROVIDER_KEY;
            wfp::FwpmSubLayerDeleteByKey0(self.handle, &sub_key);
            wfp::FwpmProviderDeleteByKey0(self.handle, &prov_key);

            let mut provider_name = wide("NetGuard");
            let mut provider_desc = wide("NetGuard 应用级网络访问控制");
            let mut provider: wfp::FWPM_PROVIDER0 = std::mem::zeroed();
            // 持久化过滤器只能引用同样持久化的 Provider 与子层，
            // 否则 FwpmFilterAdd0 返回 FWP_E_LIFETIME_MISMATCH (0x80320016)。
            provider.flags = wfp::FWPM_PROVIDER_FLAG_PERSISTENT;
            provider.providerKey = PROVIDER_KEY;
            provider.displayData.name = provider_name.as_mut_ptr();
            provider.displayData.description = provider_desc.as_mut_ptr();
            let code = wfp::FwpmProviderAdd0(self.handle, &provider, ptr::null_mut());
            if code != ERROR_SUCCESS && code != FWP_E_ALREADY_EXISTS {
                return check(code);
            }

            let mut sub_name = wide("NetGuard 出站阻断");
            let mut sub_desc = wide("NetGuard 持久化过滤器集合");
            let mut provider_key = PROVIDER_KEY;
            let mut sublayer: wfp::FWPM_SUBLAYER0 = std::mem::zeroed();
            sublayer.flags = wfp::FWPM_SUBLAYER_FLAG_PERSISTENT;
            sublayer.subLayerKey = SUBLAYER_KEY;
            sublayer.displayData.name = sub_name.as_mut_ptr();
            sublayer.displayData.description = sub_desc.as_mut_ptr();
            sublayer.providerKey = &mut provider_key as *mut GUID;
            sublayer.weight = u16::MAX;
            let code = wfp::FwpmSubLayerAdd0(self.handle, &sublayer, ptr::null_mut());
            if code != ERROR_SUCCESS && code != FWP_E_ALREADY_EXISTS {
                return check(code);
            }
            Ok(())
        }
    }

    /// 为指定可执行文件添加阻断过滤器，按需覆盖 IPv4 / IPv6 层，返回过滤器标识。
    ///
    /// 只补齐缺失的层：若某路径已有 IPv4 过滤器而缺 IPv6，重复添加双栈会产生
    /// 多余的 IPv4 过滤器，且多余项以后既不会被使用也不会被清理。
    pub fn add_block_layers(&self, app_path: &str, want_v4: bool, want_v6: bool) -> io::Result<Vec<u64>> {
        let path = wide(app_path);
        let mut blob: *mut wfp::FWP_BYTE_BLOB = ptr::null_mut();
        unsafe {
            let code = wfp::FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob);
            check(code)?;
        }
        if blob.is_null() {
            return Err(io::Error::other("无法为该路径生成应用标识"));
        }

        let result = unsafe {
            let mut condition: wfp::FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            condition.fieldKey = wfp::FWPM_CONDITION_ALE_APP_ID;
            condition.matchType = wfp::FWP_MATCH_EQUAL;
            condition.conditionValue.r#type = wfp::FWP_BYTE_BLOB_TYPE;
            condition.conditionValue.Anonymous.byteBlob = blob;

            let mut ids = Vec::with_capacity(2);
            let mut first_err = None;
            let mut layers = Vec::with_capacity(2);
            if want_v4 {
                layers.push((wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4, format!("{NAME_V4}{app_path}")));
            }
            if want_v6 {
                layers.push((wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6, format!("{NAME_V6}{app_path}")));
            }
            for (layer, name) in layers {
                match self.add_one(layer, &name, &mut condition) {
                    Ok(id) => ids.push(id),
                    Err(err) => first_err = first_err.or(Some(err)),
                }
            }
            wfp::FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut c_void);
            match first_err {
                Some(err) => Err(err),
                None => Ok(ids),
            }
        };
        result
    }

    unsafe fn add_one(
        &self,
        layer: GUID,
        name: &str,
        condition: &mut wfp::FWPM_FILTER_CONDITION0,
    ) -> io::Result<u64> {
        let mut display = wide(name);
        let mut provider_key = PROVIDER_KEY;
        let mut filter: wfp::FWPM_FILTER0 = std::mem::zeroed();
        filter.displayData.name = display.as_mut_ptr();
        filter.providerKey = &mut provider_key as *mut GUID;
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.numFilterConditions = 1;
        filter.filterCondition = condition;
        filter.action.r#type = wfp::FWP_ACTION_BLOCK;
        filter.flags = wfp::FWPM_FILTER_FLAG_PERSISTENT;

        let mut id: u64 = 0;
        let code = wfp::FwpmFilterAdd0(self.handle, &filter, ptr::null_mut(), &mut id);
        check(code)?;
        Ok(id)
    }

    /// 按标识删除过滤器。已被删除视为成功。
    pub fn delete_filter(&self, id: u64) -> io::Result<()> {
        unsafe {
            let code = wfp::FwpmFilterDeleteById0(self.handle, id);
            if code == ERROR_SUCCESS {
                return Ok(());
            }
            if code == FWP_E_FILTER_NOT_FOUND {
                return Ok(());
            }
            let err = io::Error::from_raw_os_error(code as i32);
            if is_code(&err, ERROR_NOT_FOUND) {
                return Ok(());
            }
            Err(err)
        }
    }

    /// 枚举本程序的全部过滤器（按 IPv4 / IPv6 两个层分别枚举）。
    ///
    /// 这里不能只把 `providerKey` 填进一个 `zeroed()` 的模板：`actionMask` 的语义是
    /// 「过滤器的动作类型与掩码按位与后至少有一位非零才返回」，`actionMask == 0` 与任何
    /// 动作类型相与都是 0，结果一条也枚举不到，`existing()` 永远返回空集合，
    /// `reconcile()` 于是每启动一次就再补一对，持久化过滤器无限累积。
    /// 依据（MSDN，FWPM_FILTER_ENUM_TEMPLATE0 / actionMask）：
    /// "Only filters whose action type contains at least one of the bits in actionMask
    /// will be returned" … "0xFFFFFFFF | Ignore the filter's action type when enumerating".
    ///
    /// 同理 `layerKey` 留零 GUID 的语义文档未定义，所以显式按两个层分别枚举，
    /// 不依赖「零 GUID = 全部层」这类未写明的行为。
    pub fn existing(&self) -> io::Result<Vec<Existing>> {
        let mut found = Vec::new();
        for (layer, ipv6) in [
            (wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
            (wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
        ] {
            let items = unsafe { self.enumerate_layer(layer, ipv6)? };
            found.extend(items);
        }
        Ok(found)
    }

    /// 枚举某一层上属于本 Provider 的过滤器。
    unsafe fn enumerate_layer(&self, layer: GUID, ipv6: bool) -> io::Result<Vec<Existing>> {
        let mut provider_key = PROVIDER_KEY;
        let mut template: wfp::FWPM_FILTER_ENUM_TEMPLATE0 = std::mem::zeroed();
        template.providerKey = &mut provider_key;
        template.layerKey = layer;
        // 0 == FWP_FILTER_ENUM_FULLY_CONTAINED：模板条件为空时即「该层内全部过滤器」。
        template.enumType = wfp::FWP_FILTER_ENUM_FULLY_CONTAINED;
        template.flags = 0;
        // MSDN：If zero, then all filters match。
        template.numFilterConditions = 0;
        template.filterCondition = ptr::null_mut();
        // 全 1 = 忽略动作类型；留 0 会一条都枚举不到（本次故障的根因）。
        template.actionMask = u32::MAX;
        // 只在按 callout 枚举时才需要，否则必须为空。
        template.calloutKey = ptr::null_mut();

        let mut enum_handle: HANDLE = std::mem::zeroed();
        let code = wfp::FwpmFilterCreateEnumHandle0(self.handle, &template, &mut enum_handle);
        if code == FWP_E_FILTER_NOT_FOUND || code == FWP_E_NEVER_MATCH {
            // 该层上一条都没有：空集合，不是错误。
            return Ok(Vec::new());
        }
        check(code)?;
        if enum_handle.is_null() {
            return Ok(Vec::new());
        }

        let mut found = Vec::new();
        let mut failure: Option<u32> = None;
        loop {
            let mut entries: *mut *mut wfp::FWPM_FILTER0 = ptr::null_mut();
            let mut returned: u32 = 0;
            let code = wfp::FwpmFilterEnum0(self.handle, enum_handle, ENUM_BATCH, &mut entries, &mut returned);
            if code != ERROR_SUCCESS {
                if !entries.is_null() {
                    wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
                }
                // 枚举到末尾时 WFP 用「找不到」表达，属正常结束；其它错误必须上报，
                // 否则会被当成空集合，再次退化成「每次启动都重加一对」。
                if code != FWP_E_FILTER_NOT_FOUND && code != FWP_E_NEVER_MATCH {
                    failure = Some(code);
                }
                break;
            }
            if entries.is_null() || returned == 0 {
                if !entries.is_null() {
                    wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
                }
                break;
            }
            for index in 0..returned as usize {
                let entry = *entries.add(index);
                if entry.is_null() {
                    continue;
                }
                let name = read_wide((*entry).displayData.name);
                let path = if let Some(rest) = name.strip_prefix(NAME_V6) {
                    rest
                } else if let Some(rest) = name.strip_prefix(NAME_V4) {
                    rest
                } else {
                    continue;
                };
                found.push(Existing {
                    path: path.to_string(),
                    ipv6,
                    filter_id: (*entry).filterId,
                });
            }
            let last_page = returned < ENUM_BATCH;
            wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
            if last_page {
                break;
            }
        }
        wfp::FwpmFilterDestroyEnumHandle0(self.handle, enum_handle);
        match failure {
            Some(code) => Err(io::Error::from_raw_os_error(code as i32)),
            None => Ok(found),
        }
    }

    /// 使实际过滤器集合与期望路径集合一致：删除多余/重复、补齐缺失。
    ///
    /// 去重是必需的：历史版本因枚举模板的 `actionMask` 恒为 0 而始终枚举不到过滤器，
    /// 每启动一次就再添加一对，真机上已堆积多份同名过滤器。这里对每条路径每一层只保留
    /// `filter_id` 最小的一条（稳定、可复现），其余全部删除，从而实现自愈。
    pub fn reconcile(&self, wanted: &[String]) -> io::Result<ReconcileReport> {
        self.ensure_provider_sublayer()?;
        let existing = self.existing()?;
        let mut report = ReconcileReport {
            observed: existing.len(),
            ..ReconcileReport::default()
        };

        // 先把要删的 id 收进 Vec，等枚举缓冲区（`entries`）全部释放后再统一删除：
        // 在缓冲区仍存活时删除过滤器会让后续读取悬垂内存。
        let mut stale: Vec<u64> = Vec::new();

        // 1) 同路径同层多于一条时，只留 filter_id 最小的一条。
        for path in wanted {
            for ipv6 in [false, true] {
                let mut ids: Vec<u64> = existing
                    .iter()
                    .filter(|item| &item.path == path && item.ipv6 == ipv6)
                    .map(|item| item.filter_id)
                    .collect();
                ids.sort_unstable();
                stale.extend(ids.iter().skip(1).copied());
            }
        }

        // 2) 不在期望集合里的路径整组删除（含其重复项）。
        for item in &existing {
            if !wanted.iter().any(|path| path == &item.path) {
                stale.push(item.filter_id);
            }
        }

        stale.sort_unstable();
        stale.dedup();
        for id in &stale {
            self.delete_filter(*id)?;
            report.removed += 1;
        }

        // 3) 补齐缺失的层。只看去重后存活的项。
        for path in wanted {
            let mut has_v4 = false;
            let mut has_v6 = false;
            for item in &existing {
                if &item.path != path || stale.contains(&item.filter_id) {
                    continue;
                }
                if item.ipv6 {
                    has_v6 = true;
                } else {
                    has_v4 = true;
                }
            }
            if has_v4 && has_v6 {
                report.kept += 1;
            } else {
                self.add_block_layers(path, !has_v4, !has_v6)?;
                report.added += 1;
            }
        }
        Ok(report)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                wfp::FwpmEngineClose0(self.handle);
            }
        }
    }
}

/// 生成带 `ng4|` / `ng6|` 前缀的显示名，供外部核对。
pub fn display_name(path: &str, ipv6: bool) -> String {
    let prefix = if ipv6 { NAME_V6 } else { NAME_V4 };
    format!("{prefix}{path}")
}

/// 过滤器显示名最大长度，用于日志截断。
pub fn describe(report: ReconcileReport) -> String {
    format!(
        "原有 {} 条，新增 {} 条，删除 {} 条，保持 {} 项",
        report.observed, report.added, report.removed, report.kept
    )
}

/// 供服务层使用的引擎打开包装：失败时记录日志并返回错误。
pub fn open_logged(logger: &crate::log::Logger) -> io::Result<Engine> {
    match Engine::open() {
        Ok(engine) => {
            logger.info("过滤器引擎已打开");
            Ok(engine)
        }
        Err(err) => {
            logger.error(&format!("打开过滤器引擎失败：{err}"));
            Err(err)
        }
    }
}

/// 便捷函数：读取配置文件中的路径集合。
pub fn wanted_paths(config: &netguard_core::Config) -> Vec<String> {
    config
        .apps
        .iter()
        .map(|app| app.path.clone())
        .filter(|path| !path.trim().is_empty())
        .collect()
}
