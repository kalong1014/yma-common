#![deny(missing_docs)]
//! 文件上传处理模块，支持文件类型验证、大小限制与图片缩略图生成

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// 文件上传配置
#[derive(Debug, Clone)]
pub struct UploadConfig {
    /// 最大文件大小（字节），默认10MB
    pub max_file_size: u64,
    /// 允许的文件扩展名集合（不含点，小写），如 {"jpg", "png", "pdf"}
    pub allowed_extensions: HashSet<String>,
    /// 文件上传目标目录
    pub upload_dir: PathBuf,
    /// 允许的MIME类型集合，为空表示不限制
    pub allowed_mime_types: HashSet<String>,
}

impl Default for UploadConfig {
    fn default() -> Self {
        let mut allowed_extensions = HashSet::new();
        allowed_extensions.insert("jpg".to_string());
        allowed_extensions.insert("jpeg".to_string());
        allowed_extensions.insert("png".to_string());
        allowed_extensions.insert("gif".to_string());
        allowed_extensions.insert("webp".to_string());
        allowed_extensions.insert("pdf".to_string());
        allowed_extensions.insert("txt".to_string());
        allowed_extensions.insert("csv".to_string());
        allowed_extensions.insert("json".to_string());
        allowed_extensions.insert("zip".to_string());

        Self {
            max_file_size: 10 * 1024 * 1024,
            allowed_extensions,
            upload_dir: PathBuf::from("./uploads"),
            allowed_mime_types: HashSet::new(),
        }
    }
}

/// 上传结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadResult {
    /// 原始文件名
    pub original_name: String,
    /// 存储的文件名（UUID格式避免冲突）
    pub stored_name: String,
    /// 文件存储路径
    pub file_path: String,
    /// 文件大小（字节）
    pub file_size: u64,
    /// MIME类型
    pub mime_type: String,
    /// 文件扩展名
    pub extension: String,
}

/// 验证文件扩展名是否在允许列表中
///
/// # 参数
/// * `filename` - 文件名
/// * `allowed` - 允许的扩展名集合
///
/// # 返回值
/// 成功返回小写扩展名，失败返回错误描述
pub fn validate_extension(
    filename: &str,
    allowed: &HashSet<String>,
) -> Result<String, String> {
    let path = Path::new(filename);
    let ext = match path.extension() {
        Some(ext) => ext.to_string_lossy().to_lowercase(),
        None => return Err("文件缺少扩展名".to_string()),
    };

    if ext.is_empty() {
        return Err("文件扩展名为空".to_string());
    }

    if allowed.is_empty() || allowed.contains(&ext) {
        Ok(ext)
    } else {
        Err(format!(
            "不允许的文件类型: .{}，允许的类型: {}",
            ext,
            allowed
                .iter()
                .map(|s| format!(".{}", s))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// 验证文件大小是否在限制范围内
///
/// # 参数
/// * `file_size` - 文件大小（字节）
/// * `max_size` - 最大允许大小（字节）
pub fn validate_file_size(file_size: u64, max_size: u64) -> Result<(), String> {
    if file_size == 0 {
        return Err("文件大小为0，不允许上传空文件".to_string());
    }
    if file_size > max_size {
        let max_mb = max_size as f64 / (1024.0 * 1024.0);
        let actual_mb = file_size as f64 / (1024.0 * 1024.0);
        return Err(format!(
            "文件大小 {:.2}MB 超过限制 {:.2}MB",
            actual_mb, max_mb
        ));
    }
    Ok(())
}

/// 生成唯一存储文件名
///
/// # 参数
/// * `original_name` - 原始文件名
///
/// # 返回值
/// UUID v4格式的唯一文件名，保留原始扩展名
pub fn generate_stored_name(original_name: &str) -> String {
    let ext = Path::new(original_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    format!("{}.{}", uuid::Uuid::new_v4(), ext)
}

/// 确保上传目录存在
pub async fn ensure_upload_dir(path: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|e| format!("创建上传目录失败: {}", e))
}

/// 保存上传文件
///
/// # 参数
/// * `data` - 文件字节数据
/// * `original_name` - 原始文件名
/// * `config` - 上传配置
/// * `mime_type` - MIME类型字符串
///
/// # 返回值
/// 上传结果信息
pub async fn save_uploaded_file(
    data: &[u8],
    original_name: &str,
    config: &UploadConfig,
    mime_type: &str,
) -> Result<UploadResult, String> {
    validate_file_size(data.len() as u64, config.max_file_size)?;

    let extension = validate_extension(original_name, &config.allowed_extensions)?;

    if !config.allowed_mime_types.is_empty() && !config.allowed_mime_types.contains(mime_type) {
        return Err(format!("不允许的MIME类型: {}", mime_type));
    }

    ensure_upload_dir(&config.upload_dir).await?;

    let stored_name = generate_stored_name(original_name);
    let file_path = config.upload_dir.join(&stored_name);

    tokio::fs::write(&file_path, data)
        .await
        .map_err(|e| format!("写入文件失败: {}", e))?;

    Ok(UploadResult {
        original_name: original_name.to_string(),
        stored_name,
        file_path: file_path.to_string_lossy().to_string(),
        file_size: data.len() as u64,
        mime_type: mime_type.to_string(),
        extension,
    })
}

/// 生成缩略图（仅feature thumbnail启用时编译）
///
/// # 参数
/// * `image_data` - 原始图片字节数据
/// * `max_width` - 缩略图最大宽度
/// * `max_height` - 缩略图最大高度
///
/// # 返回值
/// 缩略图PNG格式字节数据
#[cfg(feature = "thumbnail")]
pub fn generate_thumbnail(
    image_data: &[u8],
    max_width: u32,
    max_height: u32,
) -> Result<Vec<u8>, String> {
    let img = image::load_from_memory(image_data)
        .map_err(|e| format!("图片解码失败: {}", e))?;

    let thumbnail = img.thumbnail(max_width, max_height);
    let mut buf = std::io::Cursor::new(Vec::new());
    thumbnail
        .write_to(&mut buf, image::ImageFormat::Png)
        .map_err(|e| format!("缩略图写入失败: {}", e))?;

    Ok(buf.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_extension_allowed() {
        let mut allowed = HashSet::new();
        allowed.insert("jpg".to_string());
        allowed.insert("png".to_string());

        assert_eq!(validate_extension("photo.jpg", &allowed).unwrap(), "jpg");
        assert_eq!(validate_extension("PHOTO.JPG", &allowed).unwrap(), "jpg");
        assert_eq!(validate_extension("image.PNG", &allowed).unwrap(), "png");
    }

    #[test]
    fn test_validate_extension_not_allowed() {
        let mut allowed = HashSet::new();
        allowed.insert("jpg".to_string());

        assert!(validate_extension("file.exe", &allowed).is_err());
        assert!(validate_extension("script.php", &allowed).is_err());
    }

    #[test]
    fn test_validate_extension_no_extension() {
        let mut allowed = HashSet::new();
        allowed.insert("jpg".to_string());

        assert!(validate_extension("noextension", &allowed).is_err());
    }

    #[test]
    fn test_validate_file_size_ok() {
        assert!(validate_file_size(1024, 10 * 1024 * 1024).is_ok());
        assert!(validate_file_size(10 * 1024 * 1024, 10 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_file_size_zero() {
        assert!(validate_file_size(0, 10 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_validate_file_size_exceeded() {
        assert!(validate_file_size(11 * 1024 * 1024, 10 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_generate_stored_name() {
        let name = generate_stored_name("test.jpg");
        assert!(name.ends_with(".jpg"));
        assert!(name.len() > 5);
    }

    #[test]
    fn test_generate_stored_name_no_extension() {
        let name = generate_stored_name("noextension");
        assert!(name.ends_with(".bin"));
    }

    #[test]
    fn test_upload_config_default() {
        let config = UploadConfig::default();
        assert_eq!(config.max_file_size, 10 * 1024 * 1024);
        assert!(config.allowed_extensions.contains("jpg"));
        assert!(config.allowed_extensions.contains("png"));
        assert!(config.allowed_extensions.contains("pdf"));
    }
}