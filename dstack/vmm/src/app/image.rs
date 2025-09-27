use fs_err as fs;
use path_absolutize::Absolutize;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub cmdline: Option<String>,    // 内核启动命令行参数
    pub kernel: String,             // 内核文件路径
    pub initrd: String,             // 初始化 RAM 磁盘路径
    pub hda: Option<String>,        // 硬盘镜像路径
    pub rootfs: Option<String>,     // 根文件系统路径
    pub bios: Option<String>,       // BIOS 文件路径
    #[serde(default)]
    pub rootfs_hash: Option<String>,// 根文件系统的哈希值
    #[serde(default)]
    pub shared_ro: bool,            // 是否以只读方式挂载共享目录   
    #[serde(default)]
    pub version: String,            // 镜像版本
    #[serde(default)]
    pub is_dev: bool,               // 是否为开发版本   
}
//将版本字符串解析为三元组
impl ImageInfo {
    pub fn version_tuple(&self) -> Option<(u16, u16, u16)> {
        let version = self
            .version
            .split('.')
            .take(3)
            .map(|v| v.parse::<u16>())
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if version.len() < 3 {
            return None;
        }
        Some((version[0], version[1], version[2]))
    }
}
//从指定的 JSON 文件中加载镜像元数据
impl ImageInfo {
    pub fn load(filename: impl AsRef<Path>) -> Result<Self> {
        let file = fs::File::open(filename.as_ref()).context("failed to open image info")?;
        let info: ImageInfo =
            serde_json::from_reader(file).context("failed to parse image info")?;
        Ok(info)
    }
}

#[derive(Debug)]
pub struct Image {
    pub info: ImageInfo,        // 镜像元数据
    pub initrd: PathBuf,        // 绝对路径：initrd
    pub kernel: PathBuf,        // 绝对路径：kernel
    pub hda: Option<PathBuf>,   // 绝对路径：硬盘镜像
    pub rootfs: Option<PathBuf>,// 绝对路径：根文件系统
    pub bios: Option<PathBuf>,  // 绝对路径：BIOS
    pub digest: Option<String>, // 镜像摘要值
}
//镜像加载
impl Image {
    pub fn load(base_path: impl AsRef<Path>) -> Result<Self> {
        let base_path = base_path.as_ref().absolutize()?;
        let mut info = ImageInfo::load(base_path.join("metadata.json"))?;
        let initrd = base_path.join(&info.initrd);
        let kernel = base_path.join(&info.kernel);
        let hda = info.hda.as_ref().map(|hda| base_path.join(hda));
        let rootfs = info.rootfs.as_ref().map(|rootfs| base_path.join(rootfs));
        let bios = info.bios.as_ref().map(|bios| base_path.join(bios));
        let digest = fs::read_to_string(base_path.join("digest.txt"))
            .ok()
            .map(|s| s.trim().to_string());
        if info.version.is_empty() {
            // Older images does not have version field. Fallback to the version of the image folder name
            info.version = guess_version(&base_path).unwrap_or_default();
        }
        Self {
            info,
            hda,
            initrd,
            kernel,
            rootfs,
            bios,
            digest,
        }
        .ensure_exists()
    }
    //确保所有必要的文件都存在
    fn ensure_exists(self) -> Result<Self> {
        if !self.initrd.exists() {
            bail!("Initrd does not exist: {}", self.initrd.display());
        }
        if !self.kernel.exists() {
            bail!("Kernel does not exist: {}", self.kernel.display());
        }
        if let Some(hda) = &self.hda {
            if !hda.exists() {
                bail!("Hda does not exist: {}", hda.display());
            }
        }
        if let Some(rootfs) = &self.rootfs {
            if !rootfs.exists() {
                bail!("Rootfs does not exist: {}", rootfs.display());
            }
        }
        if let Some(bios) = &self.bios {
            if !bios.exists() {
                bail!("Bios does not exist: {}", bios.display());
            }
        }
        Ok(self)
    }
}
//根据镜像文件夹的名称猜测版本号
fn guess_version(base_path: &Path) -> Option<String> {
    // name pattern: dstack-dev-0.2.3 or dstack-0.2.3
    let basename = base_path.file_name()?.to_str()?.to_string();
    let version = if basename.starts_with("dstack-dev-") {
        basename.strip_prefix("dstack-dev-")?
    } else if basename.starts_with("dstack-") {
        basename.strip_prefix("dstack-")?
    } else {
        return None;
    };
    Some(version.to_string())
}
