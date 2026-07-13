#![deny(missing_docs)]
//! Meilisearch搜索客户端封装，提供索引管理、文档搜索与分页查询

use meilisearch_sdk::{
    client::Client,
    indexes::Index,
    search::SearchResults,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use yma_pagination::Pagination;

/// Meilisearch搜索客户端配置
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Meilisearch服务地址，如 "http://localhost:7700"
    pub host: String,
    /// API密钥
    pub api_key: Option<String>,
    /// 默认每页记录数
    pub default_page_size: u64,
    /// 最大每页记录数
    pub max_page_size: u64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            host: "http://localhost:7700".to_string(),
            api_key: None,
            default_page_size: 20,
            max_page_size: 100,
        }
    }
}

/// 搜索结果（带分页）
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchResponse<T: Serialize> {
    /// 匹配结果列表
    pub hits: Vec<T>,
    /// 总命中数
    pub total_hits: u64,
    /// 分页信息
    pub pagination: yma_pagination::Pagination,
    /// 查询耗时毫秒
    pub processing_time_ms: u64,
    /// 搜索查询字符串
    pub query: String,
}

/// 索引统计信息
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexStats {
    /// 索引名称
    pub name: String,
    /// 文档数量
    pub number_of_documents: u64,
    /// 是否正在索引中
    pub is_indexing: bool,
    /// 索引字段分布
    pub field_distribution: std::collections::HashMap<String, u64>,
}

/// Meilisearch搜索客户端封装
pub struct SearchClient {
    client: Client,
    config: SearchConfig,
}

impl SearchClient {
    /// 创建搜索客户端
    ///
    /// # 参数
    /// * `config` - 搜索配置
    pub fn new(config: SearchConfig) -> Self {
        let client = Client::new(&config.host, config.api_key.as_deref());
        Self { client, config }
    }

    /// 获取指定索引
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    pub async fn get_index(&self, uid: &str) -> Result<Index, String> {
        self.client
            .get_index(uid)
            .await
            .map_err(|e| format!("获取索引 {} 失败: {}", uid, e))
    }

    /// 创建索引
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    /// * `primary_key` - 主键字段名
    pub async fn create_index(
        &self,
        uid: &str,
        primary_key: Option<&str>,
    ) -> Result<Index, String> {
        let task = self
            .client
            .create_index(uid, primary_key)
            .await
            .map_err(|e| format!("创建索引 {} 失败: {}", uid, e))?;

        task.wait_for_completion(
            &self.client,
            None,
            None,
        )
        .await
        .map_err(|e| format!("等待索引创建完成失败: {}", e))?;

        self.get_index(uid).await
    }

    /// 添加文档到索引
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    /// * `documents` - 文档列表
    pub async fn add_documents<T: Serialize + Send + Sync>(
        &self,
        uid: &str,
        documents: &[T],
    ) -> Result<(), String> {
        let index = self.get_index(uid).await?;

        let task = index
            .add_documents(documents, Some("id"))
            .await
            .map_err(|e| format!("添加文档到索引 {} 失败: {}", uid, e))?;

        task.wait_for_completion(&self.client, None, None)
            .await
            .map_err(|e| format!("等待文档添加完成失败: {}", e))?;

        Ok(())
    }

    /// 搜索文档
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    /// * `query` - 搜索查询字符串
    /// * `page` - 页码（从1开始）
    /// * `page_size` - 每页记录数
    ///
    /// # 返回值
    /// 搜索结果，包含分页信息
    pub async fn search<T: DeserializeOwned + Serialize + Send + Sync + 'static>(
        &self,
        uid: &str,
        query: &str,
        page: u64,
        page_size: u64,
    ) -> Result<SearchResponse<T>, String> {
        let index = self.get_index(uid).await?;

        let actual_page_size = if page_size == 0 {
            self.config.default_page_size
        } else if page_size > self.config.max_page_size {
            self.config.max_page_size
        } else {
            page_size
        };

        let actual_page = if page == 0 { 1 } else { page };
        let offset = (actual_page - 1) * actual_page_size;

        let results: SearchResults<T> = meilisearch_sdk::search::SearchQuery::new(&index)
            .with_query(query)
            .with_offset(offset as usize)
            .with_limit(actual_page_size as usize)
            .build()
            .execute::<T>()
            .await
            .map_err(|e| format!("搜索失败: {}", e))?;

        let total_hits = results
            .estimated_total_hits
            .map(|v| v as u64)
            .unwrap_or(results.hits.len() as u64);

        let pagination = Pagination::new(actual_page, actual_page_size, total_hits);

        Ok(SearchResponse {
            hits: results.hits.into_iter().map(|r| r.result).collect(),
            total_hits,
            pagination,
            processing_time_ms: results.processing_time_ms as u64,
            query: query.to_string(),
        })
    }

    /// 删除索引中的所有文档
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    pub async fn delete_all_documents(&self, uid: &str) -> Result<(), String> {
        let index = self.get_index(uid).await?;

        let task = index
            .delete_all_documents()
            .await
            .map_err(|e| format!("删除索引 {} 所有文档失败: {}", uid, e))?;

        task.wait_for_completion(&self.client, None, None)
            .await
            .map_err(|e| format!("等待文档删除完成失败: {}", e))?;

        Ok(())
    }

    /// 删除指定文档
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    /// * `document_id` - 文档ID
    pub async fn delete_document(
        &self,
        uid: &str,
        document_id: &str,
    ) -> Result<(), String> {
        let index = self.get_index(uid).await?;

        let task = index
            .delete_document(document_id)
            .await
            .map_err(|e| format!("删除文档 {} 失败: {}", document_id, e))?;

        task.wait_for_completion(&self.client, None, None)
            .await
            .map_err(|e| format!("等待文档删除完成失败: {}", e))?;

        Ok(())
    }

    /// 获取索引统计信息
    ///
    /// # 参数
    /// * `uid` - 索引唯一标识
    pub async fn get_index_stats(&self, uid: &str) -> Result<IndexStats, String> {
        let index = self.get_index(uid).await?;

        let stats = index
            .get_stats()
            .await
            .map_err(|e| format!("获取索引 {} 统计信息失败: {}", uid, e))?;

        let field_distribution: std::collections::HashMap<String, u64> = stats
            .field_distribution
            .into_iter()
            .map(|(k, v)| (k, v as u64))
            .collect();

        Ok(IndexStats {
            name: uid.to_string(),
            number_of_documents: stats.number_of_documents as u64,
            is_indexing: stats.is_indexing,
            field_distribution,
        })
    }

    /// 列出所有索引
    pub async fn list_indexes(&self) -> Result<Vec<String>, String> {
        let indexes = self
            .client
            .list_all_indexes()
            .await
            .map_err(|e| format!("列出索引失败: {}", e))?;

        Ok(indexes
            .results
            .into_iter()
            .map(|idx| idx.uid)
            .collect())
    }

    /// 检查服务健康状态
    pub async fn health_check(&self) -> Result<bool, String> {
        self.client
            .health()
            .await
            .map(|health| health.status == "available")
            .map_err(|e| format!("健康检查失败: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_config_default() {
        let config = SearchConfig::default();
        assert_eq!(config.host, "http://localhost:7700");
        assert!(config.api_key.is_none());
        assert_eq!(config.default_page_size, 20);
        assert_eq!(config.max_page_size, 100);
    }

    #[test]
    fn test_search_config_with_api_key() {
        let config = SearchConfig {
            host: "http://search.example.com:7700".to_string(),
            api_key: Some("master_key".to_string()),
            default_page_size: 10,
            max_page_size: 50,
        };
        assert_eq!(config.host, "http://search.example.com:7700");
        assert_eq!(config.api_key, Some("master_key".to_string()));
    }

    #[test]
    fn test_create_client() {
        let config = SearchConfig::default();
        let _client = SearchClient::new(config);
    }

    #[test]
    fn test_index_stats_serialization() {
        let mut field_distribution = std::collections::HashMap::new();
        field_distribution.insert("title".to_string(), 100u64);
        field_distribution.insert("content".to_string(), 80u64);

        let stats = IndexStats {
            name: "test_index".to_string(),
            number_of_documents: 100,
            is_indexing: false,
            field_distribution,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: IndexStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test_index");
        assert_eq!(parsed.number_of_documents, 100);
        assert!(!parsed.is_indexing);
    }
}