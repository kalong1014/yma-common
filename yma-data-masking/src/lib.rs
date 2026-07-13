#![deny(missing_docs)]
//! 敏感数据脱敏模块，提供手机号、邮箱、身份证、银行卡、姓名、IP地址
//! 及通用字符串的脱敏处理功能。

/// 对中国大陆手机号进行脱敏处理。
///
/// # 参数
/// * `phone` - 待脱敏的手机号字符串
///
/// # 返回值
/// 脱敏后的字符串。标准11位手机号格式为 "138****1234"。
///
/// # 示例
/// - "13812341234" → "138****1234"
/// - "138123412" (9位) → "138****412"
pub fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    let len = chars.len();

    if len < 7 {
        return phone.to_string();
    }

    if len == 11 {
        let mut result = String::with_capacity(11);
        result.push(chars[0]);
        result.push(chars[1]);
        result.push(chars[2]);
        result.push_str("****");
        result.push(chars[7]);
        result.push(chars[8]);
        result.push(chars[9]);
        result.push(chars[10]);
        return result;
    }

    let mut result = String::new();
    result.push(chars[0]);
    result.push(chars[1]);
    result.push(chars[2]);
    result.push_str("****");
    result.push(chars[len - 3]);
    result.push(chars[len - 2]);
    result.push(chars[len - 1]);
    result
}

/// 对邮箱地址的本地部分进行脱敏处理。
///
/// # 参数
/// * `email` - 待脱敏的邮箱地址字符串
///
/// # 返回值
/// 脱敏后的字符串。
///
/// # 示例
/// - "john.doe@example.com" → "j***e@example.com"
/// - "ab@example.com" → "a***b@example.com"
pub fn mask_email(email: &str) -> String {
    let at_pos = email.find('@');
    if at_pos.is_none() {
        return email.to_string();
    }
    let at_pos = at_pos.unwrap();
    let local = &email[..at_pos];
    let domain = &email[at_pos..];

    let local_len = local.chars().count();

    match local_len {
        0 => domain.to_string(),
        1 => format!("{local}{domain}"),
        _ => {
            let first_char = local.chars().next().unwrap();
            let last_char = local.chars().last().unwrap();
            format!("{first_char}***{last_char}{domain}")
        }
    }
}

/// 对身份证号码进行脱敏处理。
///
/// # 参数
/// * `id` - 待脱敏的身份证号字符串
///
/// # 返回值
/// 脱敏后的字符串。
///
/// # 示例
/// - "110101199001011234" → "110************234"
pub fn mask_id_card(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    let len = chars.len();

    if len < 7 {
        return id.to_string();
    }

    if len == 18 {
        let mut result = String::with_capacity(18);
        result.push(chars[0]);
        result.push(chars[1]);
        result.push(chars[2]);
        for _ in 0..12 {
            result.push('*');
        }
        result.push(chars[15]);
        result.push(chars[16]);
        result.push(chars[17]);
        return result;
    }

    let mut result = String::new();
    result.push(chars[0]);
    result.push(chars[1]);
    result.push(chars[2]);
    let star_count = len - 6;
    for _ in 0..star_count {
        result.push('*');
    }
    result.push(chars[len - 3]);
    result.push(chars[len - 2]);
    result.push(chars[len - 1]);
    result
}

/// 对银行卡号进行脱敏处理。
///
/// # 参数
/// * `card` - 待脱敏的银行卡号字符串
///
/// # 返回值
/// 脱敏后的字符串。
///
/// # 示例
/// - "6222021234567890" → "6222****7890"
pub fn mask_bank_card(card: &str) -> String {
    let chars: Vec<char> = card.chars().collect();
    let len = chars.len();

    if len < 9 {
        return card.to_string();
    }

    let mut result = String::new();
    result.push(chars[0]);
    result.push(chars[1]);
    result.push(chars[2]);
    result.push(chars[3]);
    result.push_str("****");
    result.push(chars[len - 4]);
    result.push(chars[len - 3]);
    result.push(chars[len - 2]);
    result.push(chars[len - 1]);
    result
}

/// 对中文姓名进行脱敏处理。
///
/// # 参数
/// * `name` - 待脱敏的姓名字符串
///
/// # 返回值
/// 脱敏后的字符串。
///
/// # 示例
/// - "张三" → "张*"
/// - "张三丰" → "张*丰"
pub fn mask_name(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let len = chars.len();

    match len {
        0 => String::new(),
        1 => name.to_string(),
        2 => format!("{}*", chars[0]),
        _ => {
            let star_count = len - 2;
            let mut result = String::new();
            result.push(chars[0]);
            for _ in 0..star_count {
                result.push('*');
            }
            result.push(chars[len - 1]);
            result
        }
    }
}

/// 对IP地址进行部分脱敏处理。
///
/// # 参数
/// * `ip` - 待脱敏的IP地址字符串
///
/// # 返回值
/// 脱敏后的字符串。
///
/// # 示例
/// - "192.168.1.100" → "192.168.1.***"
pub fn mask_ip(ip: &str) -> String {
    match ip.rfind('.') {
        Some(pos) => format!("{}.***", &ip[..pos]),
        None => "***.***.***.***".to_string(),
    }
}

/// 通用字符串脱敏，保留首尾指定数量字符，中间用星号替代。
///
/// # 参数
/// * `s` - 待脱敏的原始字符串
/// * `keep_start` - 保留开头的字符数量
/// * `keep_end` - 保留末尾的字符数量
///
/// # 返回值
/// 脱敏后的字符串。如果总长度不超过保留长度之和，直接返回原字符串。
pub fn mask_string(s: &str, keep_start: usize, keep_end: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    if len <= keep_start + keep_end {
        return s.to_string();
    }

    let star_count = len - keep_start - keep_end;
    let mut result = String::with_capacity(keep_start + star_count + keep_end);
    for c in chars.iter().take(keep_start) {
        result.push(*c);
    }
    for _ in 0..star_count {
        result.push('*');
    }
    for c in chars.iter().skip(len - keep_end) {
        result.push(*c);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_phone_standard() {
        assert_eq!(mask_phone("13812341234"), "138****1234");
    }

    #[test]
    fn test_mask_phone_short() {
        assert_eq!(mask_phone("12345"), "12345");
    }

    #[test]
    fn test_mask_phone_9digit() {
        assert_eq!(mask_phone("138123412"), "138****412");
    }

    #[test]
    fn test_mask_phone_empty() {
        assert_eq!(mask_phone(""), "");
    }

    #[test]
    fn test_mask_email_standard() {
        assert_eq!(mask_email("john.doe@example.com"), "j***e@example.com");
    }

    #[test]
    fn test_mask_email_two_char_local() {
        assert_eq!(mask_email("ab@example.com"), "a***b@example.com");
    }

    #[test]
    fn test_mask_email_no_at() {
        assert_eq!(mask_email("invalidemail"), "invalidemail");
    }

    #[test]
    fn test_mask_email_single_char_local() {
        assert_eq!(mask_email("a@example.com"), "a@example.com");
    }

    #[test]
    fn test_mask_id_card_standard() {
        assert_eq!(mask_id_card("110101199001011234"), "110************234");
    }

    #[test]
    fn test_mask_id_card_short() {
        assert_eq!(mask_id_card("12345"), "12345");
    }

    #[test]
    fn test_mask_id_card_nonstandard() {
        assert_eq!(mask_id_card("12345678901"), "123*****901");
    }

    #[test]
    fn test_mask_bank_card_standard() {
        assert_eq!(mask_bank_card("6222021234567890"), "6222****7890");
    }

    #[test]
    fn test_mask_bank_card_short() {
        assert_eq!(mask_bank_card("12345678"), "12345678");
    }

    #[test]
    fn test_mask_name_two_char() {
        assert_eq!(mask_name("张三"), "张*");
    }

    #[test]
    fn test_mask_name_three_char() {
        assert_eq!(mask_name("张三丰"), "张*丰");
    }

    #[test]
    fn test_mask_name_four_char() {
        assert_eq!(mask_name("欧阳明日"), "欧**日");
    }

    #[test]
    fn test_mask_name_single() {
        assert_eq!(mask_name("张"), "张");
    }

    #[test]
    fn test_mask_name_empty() {
        assert_eq!(mask_name(""), "");
    }

    #[test]
    fn test_mask_ip_standard() {
        assert_eq!(mask_ip("192.168.1.100"), "192.168.1.***");
    }

    #[test]
    fn test_mask_ip_no_dot() {
        assert_eq!(mask_ip("1921681100"), "***.***.***.***");
    }

    #[test]
    fn test_mask_string_normal() {
        assert_eq!(mask_string("abcdefgh", 2, 2), "ab****gh");
    }

    #[test]
    fn test_mask_string_short() {
        assert_eq!(mask_string("abc", 2, 2), "abc");
    }

    #[test]
    fn test_mask_string_zero_keep() {
        assert_eq!(mask_string("abcdef", 0, 2), "****ef");
    }
}