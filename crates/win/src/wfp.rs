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
/// `FWP_E_FILTER_NOT_FOUND`：枚举模板匹配不到任何对象，应视为空集合。
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0013;

const NAME_V4: &str = "ng4|";
const NAME_V6: &str = "ng6|";

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

    /// 确保 Provider 与子层存在。已存在视为成功。
    pub fn ensure_provider_sublayer(&self) -> io::Result<()> {
        unsafe {
            let mut provider_name = wide("NetGuard");
            let mut provider_desc = wide("NetGuard 应用级网络访问控制");
            let mut provider: wfp::FWPM_PROVIDER0 = std::mem::zeroed();
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

    /// 为指定可执行文件添加双栈阻断过滤器，返回过滤器标识。
    pub fn add_block(&self, app_path: &str) -> io::Result<Vec<u64>> {
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
            for (layer, name) in [
                (wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4, format!("{NAME_V4}{app_path}")),
                (wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6, format!("{NAME_V6}{app_path}")),
            ] {
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

    /// 枚举本程序的全部过滤器。
    pub fn existing(&self) -> io::Result<Vec<Existing>> {
        let mut template: wfp::FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        let mut provider_key = PROVIDER_KEY;
        template.providerKey = &mut provider_key as *mut GUID;

        unsafe {
            let mut enum_handle: HANDLE = std::mem::zeroed();
            let code = wfp::FwpmFilterCreateEnumHandle0(self.handle, &template, &mut enum_handle);
            if code == FWP_E_FILTER_NOT_FOUND {
                // 一条过滤器都还没有：空集合，不是错误。
                return Ok(Vec::new());
            }
            check(code)?;

            let mut found = Vec::new();
            loop {
                let mut entries: *mut *mut wfp::FWPM_FILTER0 = ptr::null_mut();
                let mut returned: u32 = 0;
                let code = wfp::FwpmFilterEnum0(self.handle, enum_handle, 32, &mut entries, &mut returned);
                if code != ERROR_SUCCESS || returned == 0 {
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
                    let (ipv6, path) = if let Some(rest) = name.strip_prefix(NAME_V6) {
                        (true, rest.to_string())
                    } else if let Some(rest) = name.strip_prefix(NAME_V4) {
                        (false, rest.to_string())
                    } else {
                        continue;
                    };
                    found.push(Existing {
                        path,
                        ipv6,
                        filter_id: (*entry).filterId,
                    });
                }
                wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
                if returned < 32 {
                    break;
                }
            }

            wfp::FwpmFilterDestroyEnumHandle0(self.handle, enum_handle);
            Ok(found)
        }
    }

    /// 使实际过滤器集合与期望路径集合一致：补齐缺失、删除多余。
    pub fn reconcile(&self, wanted: &[String]) -> io::Result<ReconcileReport> {
        self.ensure_provider_sublayer()?;
        let existing = self.existing()?;
        let mut report = ReconcileReport::default();

        for path in wanted {
            let have: Vec<&Existing> = existing.iter().filter(|item| &item.path == path).collect();
            let both = have.iter().any(|item| !item.ipv6) && have.iter().any(|item| item.ipv6);
            if both {
                report.kept += 1;
            } else {
                self.add_block(path)?;
                report.added += 1;
            }
        }

        for item in &existing {
            if !wanted.iter().any(|path| path == &item.path) {
                self.delete_filter(item.filter_id)?;
                report.removed += 1;
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
        "新增 {} 条，删除 {} 条，保持 {} 项",
        report.added, report.removed, report.kept
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
