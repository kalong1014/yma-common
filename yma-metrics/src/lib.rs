#![deny(missing_docs)]
//! Prometheus指标基础设施，提供计数器、直方图、仪表盘封装及HTTP导出端点

use once_cell::sync::Lazy;
use prometheus::{
    register_histogram_vec, register_int_counter,
    register_int_gauge, Encoder, Gauge, HistogramOpts, HistogramVec, IntCounter, IntGauge,
    TextEncoder, Counter,
};
use std::collections::HashMap;

/// HTTP请求计数器（按方法和路径分标签）
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "http_requests_total",
        "HTTP请求总数"
    )
    .unwrap()
});

/// HTTP请求耗时直方图（按方法和路径分标签）
pub static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP请求耗时（秒）",
        &["method", "path"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap()
});

/// 活跃连接数
pub static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "active_connections",
        "当前活跃连接数"
    )
    .unwrap()
});

/// 自定义指标管理器
pub struct MetricsRegistry {
    counters: HashMap<String, Counter>,
    gauges: HashMap<String, Gauge>,
    histograms: HashMap<String, HistogramVec>,
}

impl MetricsRegistry {
    /// 创建指标管理器
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
            gauges: HashMap::new(),
            histograms: HashMap::new(),
        }
    }

    /// 注册计数器
    ///
    /// # 参数
    /// * `name` - 指标名称
    /// * `help` - 帮助说明
    pub fn register_counter(&mut self, name: &str, help: &str) -> Result<(), String> {
        let counter = Counter::new(name, help)
            .map_err(|e| format!("注册计数器失败: {}", e))?;
        prometheus::register(Box::new(counter.clone()))
            .map_err(|e| format!("注册计数器到默认注册表失败: {}", e))?;
        self.counters.insert(name.to_string(), counter);
        Ok(())
    }

    /// 增加计数器
    ///
    /// # 参数
    /// * `name` - 指标名称
    /// * `value` - 增加值
    pub fn inc_counter(&self, name: &str, value: f64) -> Result<(), String> {
        let counter = self
            .counters
            .get(name)
            .ok_or_else(|| format!("计数器 {} 未注册", name))?;
        counter.inc_by(value);
        Ok(())
    }

    /// 注册仪表盘
    ///
    /// # 参数
    /// * `name` - 指标名称
    /// * `help` - 帮助说明
    pub fn register_gauge(&mut self, name: &str, help: &str) -> Result<(), String> {
        let gauge = Gauge::new(name, help)
            .map_err(|e| format!("注册仪表盘失败: {}", e))?;
        prometheus::register(Box::new(gauge.clone()))
            .map_err(|e| format!("注册仪表盘到默认注册表失败: {}", e))?;
        self.gauges.insert(name.to_string(), gauge);
        Ok(())
    }

    /// 设置仪表盘值
    ///
    /// # 参数
    /// * `name` - 指标名称
    /// * `value` - 设置值
    pub fn set_gauge(&self, name: &str, value: f64) -> Result<(), String> {
        let gauge = self
            .gauges
            .get(name)
            .ok_or_else(|| format!("仪表盘 {} 未注册", name))?;
        gauge.set(value);
        Ok(())
    }

    /// 注册直方图
    ///
    /// # 参数
    /// * `name` - 指标名称
    /// * `help` - 帮助说明
    /// * `label_names` - 标签名称列表
    /// * `buckets` - 桶边界值列表
    pub fn register_histogram(
        &mut self,
        name: &str,
        help: &str,
        label_names: &[&str],
        buckets: Vec<f64>,
    ) -> Result<(), String> {
        let opts = HistogramOpts::new(name, help).buckets(buckets);
        let histogram = HistogramVec::new(opts, label_names)
            .map_err(|e| format!("注册直方图失败: {}", e))?;
        prometheus::register(Box::new(histogram.clone()))
            .map_err(|e| format!("注册直方图到默认注册表失败: {}", e))?;
        self.histograms.insert(name.to_string(), histogram);
        Ok(())
    }

    /// 记录直方图观测值
    ///
    /// # 参数
    /// * `name` - 指标名称
    /// * `value` - 观测值
    /// * `labels` - 标签值列表
    pub fn observe_histogram(
        &self,
        name: &str,
        value: f64,
        labels: &[&str],
    ) -> Result<(), String> {
        let histogram = self
            .histograms
            .get(name)
            .ok_or_else(|| format!("直方图 {} 未注册", name))?;
        histogram.with_label_values(labels).observe(value);
        Ok(())
    }

    /// 收集所有指标数据为Prometheus文本格式
    pub fn gather_metrics_text(&self) -> Result<String, String> {
        let metric_families = prometheus::gather();
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| format!("编码指标失败: {}", e))?;
        String::from_utf8(buffer).map_err(|e| format!("指标数据UTF-8转换失败: {}", e))
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus指标导出HTTP handler
///
/// 返回Prometheus文本格式的所有指标数据
pub async fn metrics_handler() -> axum::response::Response {
    let metric_families = prometheus::gather();
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if encoder.encode(&metric_families, &mut buffer).is_err() {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from("指标编码失败"))
            .unwrap();
    }
    let body = String::from_utf8_lossy(&buffer).to_string();
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// HTTP请求指标中间件
///
/// 自动记录每个HTTP请求的计数和耗时
pub async fn metrics_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    HTTP_REQUESTS_TOTAL.inc();
    ACTIVE_CONNECTIONS.inc();

    let timer = std::time::Instant::now();
    let response = next.run(request).await;

    ACTIVE_CONNECTIONS.dec();
    let duration = timer.elapsed().as_secs_f64();
    HTTP_REQUEST_DURATION
        .with_label_values(&[&method, &path])
        .observe(duration);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry_new() {
        let registry = MetricsRegistry::new();
        assert!(registry.counters.is_empty());
        assert!(registry.gauges.is_empty());
        assert!(registry.histograms.is_empty());
    }

    #[test]
    fn test_register_and_inc_counter() {
        let mut registry = MetricsRegistry::new();
        let counter_name = "test_counter_1";

        registry
            .register_counter(counter_name, "测试计数器")
            .unwrap();
        assert!(registry.counters.contains_key(counter_name));

        registry.inc_counter(counter_name, 1.0).unwrap();
    }

    #[test]
    fn test_register_and_set_gauge() {
        let mut registry = MetricsRegistry::new();
        let gauge_name = "test_gauge_1";

        registry.register_gauge(gauge_name, "测试仪表盘").unwrap();
        registry.set_gauge(gauge_name, 42.0).unwrap();
    }

    #[test]
    fn test_inc_nonexistent_counter() {
        let registry = MetricsRegistry::new();
        assert!(registry.inc_counter("nonexistent", 1.0).is_err());
    }

    #[test]
    fn test_set_nonexistent_gauge() {
        let registry = MetricsRegistry::new();
        assert!(registry.set_gauge("nonexistent", 1.0).is_err());
    }

    #[test]
    fn test_register_histogram() {
        let mut registry = MetricsRegistry::new();
        registry
            .register_histogram(
                "test_histogram_1",
                "测试直方图",
                &["method"],
                vec![0.1, 0.5, 1.0],
            )
            .unwrap();

        registry
            .observe_histogram("test_histogram_1", 0.3, &["GET"])
            .unwrap();
    }

    #[test]
    fn test_gather_metrics_text() {
        let mut registry = MetricsRegistry::new();
        registry
            .register_counter("test_counter_2", "测试")
            .unwrap();

        let text = registry.gather_metrics_text().unwrap();
        assert!(text.contains("test_counter_2"));
    }

    #[test]
    fn test_http_requests_total_increment() {
        let before = HTTP_REQUESTS_TOTAL.get();
        HTTP_REQUESTS_TOTAL.inc();
        let after = HTTP_REQUESTS_TOTAL.get();
        assert_eq!(after, before + 1);
    }
}