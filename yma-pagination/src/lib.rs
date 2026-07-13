#![deny(missing_docs)]
//! 分页工具模块，提供分页参数解析、偏移量/限制计算和PaginationInfo转换。

use serde::Serialize;

/// 分页查询参数结构体。
///
/// 用于处理前端传入的分页参数，自动修正非法值。
#[derive(Debug, Clone, Serialize)]
pub struct Pagination {
    /// 当前页码，自动修正最小值1
    pub page: u64,
    /// 每页记录数，自动修正范围1-100
    pub page_size: u64,
    /// 数据源的总记录数
    pub total: u64,
    /// 总页数，根据total和page_size计算
    pub total_pages: u64,
}

impl Pagination {
    /// 创建分页实例并自动修正参数。
    ///
    /// # 参数
    /// * `page` - 请求的页码
    /// * `page_size` - 每页记录数
    /// * `total` - 数据源的总记录数
    ///
    /// # 返回值
    /// 参数修正后的Pagination实例。
    ///
    /// # 修正规则
    /// - page为0时修正为1
    /// - page_size为0时修正为20
    /// - page_size超过100时修正为100
    /// - total_pages使用向上取整计算
    pub fn new(page: u64, page_size: u64, total: u64) -> Self {
        let page = if page == 0 { 1 } else { page };
        let page_size = match page_size {
            0 => 20,
            v if v > 100 => 100,
            v => v,
        };

        let total_pages = if total == 0 {
            0
        } else {
            total.div_ceil(page_size)
        };

        Self {
            page,
            page_size,
            total,
            total_pages,
        }
    }

    /// 计算SQL查询的OFFSET值。
    ///
    /// # 返回值
    /// 公式: (page - 1) * page_size
    pub fn offset(&self) -> u64 {
        (self.page.saturating_sub(1)) * self.page_size
    }

    /// 计算SQL查询的LIMIT值。
    ///
    /// # 返回值
    /// 直接返回page_size。
    pub fn limit(&self) -> u64 {
        self.page_size
    }

    /// 转换为yma-api-response的PaginationInfo。
    ///
    /// # 返回值
    /// 包含相同四个字段的PaginationInfo实例。
    pub fn to_info(&self) -> yma_api_response::PaginationInfo {
        yma_api_response::PaginationInfo {
            page: self.page,
            page_size: self.page_size,
            total: self.total,
            total_pages: self.total_pages,
        }
    }
}

/// 解析可选的分页参数并应用默认值和修正规则。
///
/// # 参数
/// * `page` - 可选页码
/// * `page_size` - 可选每页记录数
///
/// # 返回值
/// (处理后的page, 处理后的page_size) 元组。
///
/// # 默认规则
/// - page默认为1，小于1修正为1
/// - page_size默认为20，小于1修正为1，大于100修正为100
pub fn parse_pagination_params(page: Option<u64>, page_size: Option<u64>) -> (u64, u64) {
    let page = match page {
        None => 1,
        Some(v) if v < 1 => 1,
        Some(v) => v,
    };

    let page_size = match page_size {
        None => 20,
        Some(v) if v < 1 => 1,
        Some(v) if v > 100 => 100,
        Some(v) => v,
    };

    (page, page_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_new_default() {
        let p = Pagination::new(1, 20, 100);
        assert_eq!(p.page, 1);
        assert_eq!(p.page_size, 20);
        assert_eq!(p.total, 100);
        assert_eq!(p.total_pages, 5);
    }

    #[test]
    fn test_pagination_new_page_zero() {
        let p = Pagination::new(0, 20, 100);
        assert_eq!(p.page, 1);
    }

    #[test]
    fn test_pagination_new_pagesize_zero() {
        let p = Pagination::new(1, 0, 100);
        assert_eq!(p.page_size, 20);
    }

    #[test]
    fn test_pagination_new_pagesize_exceeds_max() {
        let p = Pagination::new(1, 200, 100);
        assert_eq!(p.page_size, 100);
    }

    #[test]
    fn test_pagination_new_total_zero() {
        let p = Pagination::new(1, 20, 0);
        assert_eq!(p.total_pages, 0);
    }

    #[test]
    fn test_pagination_offset() {
        let p = Pagination::new(3, 20, 100);
        assert_eq!(p.offset(), 40);
    }

    #[test]
    fn test_pagination_limit() {
        let p = Pagination::new(1, 50, 100);
        assert_eq!(p.limit(), 50);
    }

    #[test]
    fn test_pagination_total_pages_ceiling() {
        let p = Pagination::new(1, 20, 101);
        assert_eq!(p.total_pages, 6);
    }

    #[test]
    fn test_to_info() {
        let p = Pagination::new(2, 30, 200);
        let info = p.to_info();
        assert_eq!(info.page, 2);
        assert_eq!(info.page_size, 30);
        assert_eq!(info.total, 200);
        assert_eq!(info.total_pages, 7);
    }

    #[test]
    fn test_parse_pagination_params_default() {
        let (page, page_size) = parse_pagination_params(None, None);
        assert_eq!(page, 1);
        assert_eq!(page_size, 20);
    }

    #[test]
    fn test_parse_pagination_params_invalid() {
        let (page, page_size) = parse_pagination_params(Some(0), Some(200));
        assert_eq!(page, 1);
        assert_eq!(page_size, 100);
    }

    #[test]
    fn test_parse_pagination_params_valid() {
        let (page, page_size) = parse_pagination_params(Some(5), Some(50));
        assert_eq!(page, 5);
        assert_eq!(page_size, 50);
    }
}