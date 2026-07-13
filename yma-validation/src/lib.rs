#![deny(missing_docs)]
//! 通用验证器模块，提供邮箱、URL、用户名、密码强度、手机号、身份证、
//! IPv4地址、域名、文件名等格式验证及输入清洗功能。
//!
//! # Features
//! - `chinese`: 启用中文特定验证（手机号、身份证，默认启用）

use regex::Regex;
use std::sync::LazyLock;

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

static USERNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]{2,31}$").unwrap()
});

static PHONE_CN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^1[3-9]\d{9}$").unwrap()
});

static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$").unwrap()
});

/// 验证邮箱地址是否合法。
///
/// # 参数
/// * `email` - 待验证的邮箱地址
///
/// # 返回值
/// 如果邮箱格式合法返回 `true`，否则返回 `false`。
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 320 {
        return false;
    }
    EMAIL_RE.is_match(email)
}

/// 验证URL是否合法。
///
/// # 参数
/// * `url` - 待验证的URL字符串
///
/// # 返回值
/// 如果URL以 http:// 或 https:// 开头且长度不超过2048，返回 `true`。
pub fn is_valid_url(url: &str) -> bool {
    if url.len() > 2048 {
        return false;
    }
    url.starts_with("http://") || url.starts_with("https://")
}

/// 验证用户名是否合法。
///
/// 规则: 长度3-32，以字母开头，仅允许字母、数字和下划线。
///
/// # 参数
/// * `username` - 待验证的用户名
///
/// # 返回值
/// 如果用户名格式合法返回 `true`，否则返回 `false`。
pub fn is_valid_username(username: &str) -> bool {
    USERNAME_RE.is_match(username)
}

/// 验证密码强度。
///
/// 规则: 长度8-128，必须包含大写字母、小写字母、数字和特殊字符各至少一个。
///
/// # 参数
/// * `password` - 待验证的密码
///
/// # 返回值
/// 如果密码满足强度要求返回 `true`，否则返回 `false`。
pub fn is_strong_password(password: &str) -> bool {
    let len = password.len();
    if !(8..=128).contains(&len) {
        return false;
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;

    for ch in password.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }

    has_upper && has_lower && has_digit && has_special
}

/// 验证中国大陆手机号是否合法。
///
/// # 参数
/// * `phone` - 待验证的手机号字符串
///
/// # 返回值
/// 如果手机号格式合法返回 `true`，否则返回 `false`。
#[cfg(feature = "chinese")]
pub fn is_valid_phone_cn(phone: &str) -> bool {
    PHONE_CN_RE.is_match(phone)
}

/// 验证中国大陆18位身份证号码是否合法。
///
/// 包括长度验证、格式验证和校验位验证。
///
/// # 参数
/// * `id_card` - 待验证的身份证号字符串
///
/// # 返回值
/// 如果身份证号格式合法且校验位正确返回 `true`，否则返回 `false`。
#[cfg(feature = "chinese")]
pub fn is_valid_id_card_cn(id_card: &str) -> bool {
    if id_card.len() != 18 {
        return false;
    }

    let chars: Vec<char> = id_card.chars().collect();

    for c in chars.iter().take(17) {
        if !c.is_ascii_digit() {
            return false;
        }
    }

    let last_char = chars[17];
    if !last_char.is_ascii_digit() && last_char != 'X' && last_char != 'x' {
        return false;
    }

    let weights: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let check_codes: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

    let sum: u32 = chars
        .iter()
        .take(17)
        .enumerate()
        .map(|(i, c)| c.to_digit(10).unwrap_or(0) * weights[i])
        .sum();

    let expected = check_codes[(sum % 11) as usize];
    last_char.to_ascii_uppercase() == expected
}

/// 验证IPv4地址是否合法。
///
/// # 参数
/// * `ip` - 待验证的IPv4地址字符串
///
/// # 返回值
/// 如果IP地址格式合法返回 `true`，否则返回 `false`。
pub fn is_valid_ipv4(ip: &str) -> bool {
    IPV4_RE.is_match(ip)
}

/// 验证域名是否合法。
///
/// # 参数
/// * `domain` - 待验证的域名字符串
///
/// # 返回值
/// 如果域名格式合法返回 `true`，否则返回 `false`。
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.len() > 253 {
        return false;
    }
    DOMAIN_RE.is_match(domain)
}

/// 对用户输入进行基本清洗。
///
/// 移除首尾空白，限制最大长度为1000字符。
///
/// # 参数
/// * `input` - 待清洗的输入字符串
///
/// # 返回值
/// 清洗后的字符串。
pub fn sanitize_input(input: &str) -> String {
    let trimmed = input.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() > 1000 {
        chars.iter().take(1000).collect()
    } else {
        trimmed.to_string()
    }
}

/// 验证文件名是否安全。
///
/// 规则: 不允许路径分隔符（/ 或 \），不允许空字节，不允许以点开头，不允许 ".."，长度不超过255。
///
/// # 参数
/// * `filename` - 待验证的文件名
///
/// # 返回值
/// 如果文件名安全返回 `true`，否则返回 `false`。
pub fn is_safe_filename(filename: &str) -> bool {
    if filename.is_empty() || filename.len() > 255 {
        return false;
    }
    if filename.contains('/') || filename.contains('\\') {
        return false;
    }
    if filename.contains('\0') {
        return false;
    }
    if filename.starts_with('.') {
        return false;
    }
    if filename.contains("..") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user.name+tag@domain.co.uk"));
    }

    #[test]
    fn test_invalid_email() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@nodomain.com"));
        assert!(!is_valid_email("no@tld"));
    }

    #[test]
    fn test_valid_url() {
        assert!(is_valid_url("https://example.com"));
        assert!(is_valid_url("http://localhost:8080/path"));
    }

    #[test]
    fn test_invalid_url() {
        assert!(!is_valid_url(""));
        assert!(!is_valid_url("ftp://example.com"));
        assert!(!is_valid_url("example.com"));
    }

    #[test]
    fn test_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(2100));
        assert!(!is_valid_url(&long_url));
    }

    #[test]
    fn test_valid_username() {
        assert!(is_valid_username("Alice"));
        assert!(is_valid_username("user_123"));
    }

    #[test]
    fn test_invalid_username() {
        assert!(!is_valid_username("ab"));
        assert!(!is_valid_username("1invalid"));
        assert!(!is_valid_username("user-name"));
    }

    #[test]
    fn test_strong_password() {
        assert!(is_strong_password("Password1!"));
        assert!(is_strong_password("Abcd1234#"));
    }

    #[test]
    fn test_weak_password() {
        assert!(!is_strong_password("short1!"));
        assert!(!is_strong_password("password1!"));
        assert!(!is_strong_password("PASSWORD1!"));
        assert!(!is_strong_password("Password!"));
    }

    #[test]
    fn test_valid_phone_cn() {
        assert!(is_valid_phone_cn("13812341234"));
        assert!(is_valid_phone_cn("15900001111"));
    }

    #[test]
    fn test_invalid_phone_cn() {
        assert!(!is_valid_phone_cn("12345678901"));
        assert!(!is_valid_phone_cn("1381234123"));
        assert!(!is_valid_phone_cn("138123412345"));
    }

    #[test]
    fn test_valid_id_card_cn() {
        assert!(is_valid_id_card_cn("110101199003071938"));
    }

    #[test]
    fn test_invalid_id_card_cn() {
        assert!(!is_valid_id_card_cn("12345678901234567"));
        assert!(!is_valid_id_card_cn("110101199003071939"));
        assert!(!is_valid_id_card_cn(""));
    }

    #[test]
    fn test_valid_ipv4() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("255.255.255.255"));
        assert!(is_valid_ipv4("0.0.0.0"));
    }

    #[test]
    fn test_invalid_ipv4() {
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("1.2.3.4.5"));
        assert!(!is_valid_ipv4(""));
    }

    #[test]
    fn test_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.domain.co.uk"));
    }

    #[test]
    fn test_invalid_domain() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("invalid"));
    }

    #[test]
    fn test_sanitize_input() {
        assert_eq!(sanitize_input("  hello  "), "hello");
        assert_eq!(sanitize_input("a".repeat(1001).as_str()).len(), 1000);
    }

    #[test]
    fn test_safe_filename() {
        assert!(is_safe_filename("report.txt"));
        assert!(is_safe_filename("my-file_v1.log"));
    }

    #[test]
    fn test_unsafe_filename() {
        assert!(!is_safe_filename(""));
        assert!(!is_safe_filename(".hidden"));
        assert!(!is_safe_filename("../escape.txt"));
        assert!(!is_safe_filename("path/traversal"));
    }
}