use std::{net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use load_config::load_config;
use path_absolutize::Absolutize;
use rocket::figment::Figment;
use serde::{Deserialize, Serialize};

use lspci::{lspci_filtered, Device};
use tracing::info;

pub const DEFAULT_CONFIG: &str = include_str!("../vmm.toml");
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("vmm", DEFAULT_CONFIG, config_file, false)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => bail!("Invalid protocol: {s}"),
        })
    }
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortRange {
    pub protocol: Protocol,   // 协议
    pub from: u16,            // 起始端口
    pub to: u16,              // 结束端口
}

impl PortRange {
    pub fn contains(&self, protocol: &str, port: u16) -> bool {
        self.protocol.as_str() == protocol && port >= self.from && port <= self.to
    }
}
// 端口映射配置
#[derive(Debug, Clone, Deserialize)]
pub struct PortMappingConfig {
    pub enabled: bool,          // 是否启用端口映射
    pub address: IpAddr,        // 绑定地址
    pub range: Vec<PortRange>,  // 允许的端口范围
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoRestartConfig {
    pub enabled: bool,          // 是否启用自动重启
    pub interval: u64,          // 自动重启间隔
}

impl PortMappingConfig {
    pub fn is_allowed(&self, protocol: &str, port: u16) -> bool {
        if !self.enabled {
            return false;
        }
        self.range.iter().any(|r| r.contains(protocol, port))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CvmConfig {
    pub qemu_path: PathBuf,                 // qemu 可执行文件路径  
    /// The URL of the KMS server
    pub kms_urls: Vec<String>,              // KMS 服务器 URL 列表
    /// The URL of the dstack-gateway server
    #[serde(alias = "tproxy_urls")]
    pub gateway_urls: Vec<String>,          // gateway 服务器 URL 列表   
    /// The URL of the PCCS server
    #[serde(default)]
    pub pccs_url: String,                   // PCCS 服务器 URL
    /// The URL of the Docker registry
    pub docker_registry: String,            // Docker 镜像仓库 URL  
    /// The maximum disk size in GB
    pub max_disk_size: u32,                 // 最大磁盘大小（GB）
    /// The start of the CID pool that allocates CIDs to VMs
    pub cid_start: u32,                     // CID 池起始值
    /// The size of the CID pool that allocates CIDs to VMs
    pub cid_pool_size: u32,                 // CID 池大小
    /// Port mapping configuration
    pub port_mapping: PortMappingConfig,    // 端口映射配置
    /// Max allocable resources. Not yet implement fully, only for inspect API `GetMeta`
    pub max_allocable_vcpu: u32,            // 最大可分配 CPU 核数
    pub max_allocable_memory_in_mb: u32,    // 最大可分配内存（MB）
    /// Enable qmp socket           
    pub qmp_socket: bool,                   // 启用 QMP 套接字
    /// GPU configuration
    pub gpu: GpuConfig,                     // GPU 配置 
    /// Use sudo to run the VM
    pub user: String,                       // 运行 VM 的用户   

    /// The CA certificate
    #[serde(default)]
    pub ca_cert: String,                    // CA 证书
    /// The tmp CA certificate
    #[serde(default)]
    pub tmp_ca_cert: String,                // 临时 CA 证书
    /// The tmp CA key
    #[serde(default)]
    pub tmp_ca_key: String,                 // 临时 CA 密钥

    /// Auto restart configuration
    pub auto_restart: AutoRestartConfig,    // 自动重启配置

    /// Use mrconfigid instead of compose hash
    pub use_mrconfigid: bool,               // 使用 MR Config ID
}

#[derive(Debug, Clone, Deserialize)]
pub struct GpuConfig {
    /// Whether to enable GPU passthrough
    pub enabled: bool,                      // 启用 GPU 直通
    /// The product IDs of the GPUs to discover
    pub listing: Vec<String>,               // 要发现的 GPU 产品 ID
    /// The PCI addresses to exclude from passthrough
    pub exclude: Vec<String>,               // 排除的 PCI 地址
    /// The PCI addresses to include in passthrough
    pub include: Vec<String>,               // 包含的 PCI 地址
    /// Allow attach all GPUs
    pub allow_attach_all: bool,             // 允许挂载所有 GPU
}

impl GpuConfig {
    pub(crate) fn list_devices(&self) -> Result<Vec<Device>> {
        let devices = lspci_filtered(|dev| {
            if !self.listing.contains(&dev.full_product_id()) {
                return false;
            }
            if self.exclude.contains(&dev.slot) {
                return false;
            }
            if !self.include.is_empty() && !self.include.contains(&dev.slot) {
                return false;
            }
            true
        })
        .context("Failed to list GPU devices")?;

        info!(
            "Found {} GPUs, {} in use",
            devices.len(),
            devices.iter().filter(|d| d.in_use()).count()
        );
        Ok(devices)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// Whether to enable API token authentication
    pub enabled: bool,          // 启用 API 令牌认证   
    /// The API tokens
    pub tokens: Vec<String>,    // API 令牌列表
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupervisorConfig {
    pub exe: String,            // 可执行文件路径
    pub sock: String,           // 套接字路径
    pub pid_file: String,       // PID 文件路径
    pub log_file: String,       // 日志文件路径
    pub detached: bool,         // 分离运行
    pub auto_start: bool,       // 自动启动
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub base_domain: String,    // 基础域名
    pub port: u16,              // 端口
    pub agent_port: u16,        // 代理端口
}
// 主配置
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub image_path: PathBuf,                // 镜像存储路径
    #[serde(default)]
    pub run_path: PathBuf,                  // 运行时文件路径   
    /// The URL of the KMS server
    pub kms_url: String,                    // KMS 服务器 URL

    /// CVM configuration
    pub cvm: CvmConfig,                     // CVM 配置
    /// Gateway configuration
    pub gateway: GatewayConfig,             // 网关配置

    /// Networking configuration
    pub networking: Networking,             // 网络配置

    /// Authentication configuration
    pub auth: AuthConfig,                   // 认证配置  

    /// Supervisor configuration
    pub supervisor: SupervisorConfig,       // 进程监控配置

    /// Host API configuration
    pub host_api: HostApiConfig,            // 主机 API 配置

    /// Key provider configuration
    pub key_provider: KeyProviderConfig,    // 密钥提供者配置
}

impl Config {
    pub fn abs_path(self) -> Result<Self> {
        Ok(Self {
            image_path: self.image_path.absolutize()?.to_path_buf(),
            run_path: self.run_path.absolutize()?.to_path_buf(),
            ..self
        })
    }
}

// 网络配置
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Networking {
    User(UserNetworking),       // 用户模式网络
    Custom(CustomNetworking),   // 自定义网络
}
// 用户模式网络配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserNetworking {
    pub net: String,            // 网络段
    pub dhcp_start: String,     // DHCP 起始地址
    pub restrict: bool,         // 是否限制网络访问
}
// 自定义网络配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomNetworking {
    pub netdev: String,         // 网络设备配置字符串
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostApiConfig {
    pub address: String,        // 监听地址
    pub port: u32,              // 监听端口
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyProviderConfig {
    pub enabled: bool,          // 是否启用密钥提供者
    pub address: IpAddr,        // 监听地址
    pub port: u16,              // 监听端口
}

impl Config {
    // 默认值设置
    pub fn extract_or_default(figment: &Figment) -> Result<Self> {
        let mut me: Self = figment.extract()?;
        {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            let app_home = home.join(".dstack-vmm");
            // 设置默认镜像路径
            if me.image_path == PathBuf::default() {
                me.image_path = app_home.join("image");
            }
            // 设置默认运行路径
            if me.run_path == PathBuf::default() {
                me.run_path = app_home.join("vm");
            }
            // 自动检测 QEMU 路径
            if me.cvm.qemu_path == PathBuf::default() {
                let cpu_arch = std::env::consts::ARCH;
                let qemu_path = which::which(format!("qemu-system-{}", cpu_arch))
                    .context("Failed to find qemu executable")?;
                me.cvm.qemu_path = qemu_path;
            }
        }
        Ok(me)
    }
}
