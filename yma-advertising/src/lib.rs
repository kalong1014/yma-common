//! yma-advertising 广告服务统一库
//!
//! 提供广告投放、展示、统计等标准化接口
//! 版本锁定: 0.2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;


/// 广告位类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdPlacement {
    Banner,
    Interstitial,
    Native,
    Video,
}

/// 广告请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdRequest {
    pub placement: AdPlacement,
    pub user_id: Option<String>,
    pub tags: Vec<String>,
}

/// 广告响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdResponse {
    pub ad_id: String,
    pub content_url: String,
    pub impression_url: String,
    pub click_url: String,
    pub title: String,
    pub description: String,
    pub image_url: Option<String>,
}

/// 广告素材
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdCreative {
    pub id: String,
    pub title: String,
    pub description: String,
    pub content_url: String,
    pub image_url: Option<String>,
    pub tags: Vec<String>,
    pub placement_types: Vec<AdPlacement>,
    pub weight: u32, // 权重，越高越优先展示
    pub enabled: bool,
}

/// 广告投放引擎
pub struct AdvertisingEngine {
    creatives: Arc<RwLock<HashMap<String, AdCreative>>>,
    stats: Arc<RwLock<AdStats>>,
}

/// 广告统计
#[derive(Debug, Default)]
pub struct AdStats {
    impressions: HashMap<String, u64>,
    clicks: HashMap<String, u64>,
}

impl AdvertisingEngine {
    pub fn new() -> Self {
        Self {
            creatives: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AdStats::default())),
        }
    }

    /// 注册广告素材
    pub fn register_creative(&self, creative: AdCreative) {
        self.creatives.write().insert(creative.id.clone(), creative);
    }

    /// 请求广告
    pub fn request_ad(&self, req: AdRequest) -> Option<AdResponse> {
        let creatives = self.creatives.read();

        // 筛选匹配的广告
        let mut candidates: Vec<&AdCreative> = creatives
            .values()
            .filter(|c| c.enabled)
            .filter(|c| c.placement_types.contains(&req.placement))
            .filter(|c| {
                if req.tags.is_empty() {
                    true
                } else {
                    c.tags.iter().any(|tag| req.tags.contains(tag))
                }
            })
            .collect();

        // 按权重排序
        candidates.sort_by_key(|c| std::cmp::Reverse(c.weight));

        // 返回权重最高的广告
        candidates.first().map(|creative| AdResponse {
            ad_id: creative.id.clone(),
            content_url: creative.content_url.clone(),
            impression_url: format!("/api/v1/ads/{}/impression", creative.id),
            click_url: format!("/api/v1/ads/{}/click", creative.id),
            title: creative.title.clone(),
            description: creative.description.clone(),
            image_url: creative.image_url.clone(),
        })
    }

    /// 上报展示
    pub fn report_impression(&self, ad_id: &str) {
        let mut stats = self.stats.write();
        *stats.impressions.entry(ad_id.to_string()).or_insert(0) += 1;
    }

    /// 上报点击
    pub fn report_click(&self, ad_id: &str) {
        let mut stats = self.stats.write();
        *stats.clicks.entry(ad_id.to_string()).or_insert(0) += 1;
    }

    /// 获取广告统计
    pub fn get_stats(&self, ad_id: &str) -> (u64, u64) {
        let stats = self.stats.read();
        let impressions = stats.impressions.get(ad_id).copied().unwrap_or(0);
        let clicks = stats.clicks.get(ad_id).copied().unwrap_or(0);
        (impressions, clicks)
    }

    /// 获取所有素材
    pub fn get_all_creatives(&self) -> Vec<AdCreative> {
        self.creatives.read().values().cloned().collect()
    }

    /// 移除素材
    pub fn remove_creative(&self, ad_id: &str) -> bool {
        self.creatives.write().remove(ad_id).is_some()
    }
}

impl Default for AdvertisingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertising_engine() {
        let engine = AdvertisingEngine::new();

        let creative = AdCreative {
            id: "ad_1".to_string(),
            title: "Test Ad".to_string(),
            description: "Test Description".to_string(),
            content_url: "https://example.com/ad".to_string(),
            image_url: None,
            tags: vec!["tech".to_string()],
            placement_types: vec![AdPlacement::Banner],
            weight: 10,
            enabled: true,
        };

        engine.register_creative(creative);

        let req = AdRequest {
            placement: AdPlacement::Banner,
            user_id: None,
            tags: vec!["tech".to_string()],
        };

        let response = engine.request_ad(req);
        assert!(response.is_some());
        let ad = response.unwrap();
        assert_eq!(ad.ad_id, "ad_1");
        assert_eq!(ad.title, "Test Ad");
    }

    #[test]
    fn test_ad_stats() {
        let engine = AdvertisingEngine::new();

        let creative = AdCreative {
            id: "ad_1".to_string(),
            title: "Test".to_string(),
            description: "Desc".to_string(),
            content_url: "url".to_string(),
            image_url: None,
            tags: vec![],
            placement_types: vec![AdPlacement::Banner],
            weight: 1,
            enabled: true,
        };
        engine.register_creative(creative);

        engine.report_impression("ad_1");
        engine.report_impression("ad_1");
        engine.report_click("ad_1");

        let (impressions, clicks) = engine.get_stats("ad_1");
        assert_eq!(impressions, 2);
        assert_eq!(clicks, 1);
    }

    #[test]
    fn test_no_matching_ad() {
        let engine = AdvertisingEngine::new();

        let req = AdRequest {
            placement: AdPlacement::Banner,
            user_id: None,
            tags: vec![],
        };

        let response = engine.request_ad(req);
        assert!(response.is_none());
    }
}