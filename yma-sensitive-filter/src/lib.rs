#![deny(missing_docs)]
//! 敏感词过滤器，基于Aho-Corasick自动机实现高效多模式匹配。
//!
//! 支持从词库批量构建自动机，对文本进行敏感词搜索、过滤和检测。

use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};

/// 敏感词匹配结果。
#[derive(Debug, Clone, Serialize)]
pub struct SensitiveWordMatch {
    /// 匹配到的敏感词原文
    pub word: String,
    /// 在输入文本中的起始字符索引（Unicode字符计数）
    pub start_index: usize,
    /// 在输入文本中的结束字符索引（Unicode字符计数）
    pub end_index: usize,
}

/// Trie树节点。
#[derive(Default, Clone)]
struct TrieNode {
    children: HashMap<char, usize>,
    fail_link: usize,
    outputs: HashSet<String>,
}

/// 基于Aho-Corasick自动机的敏感词过滤器。
pub struct SensitiveFilter {
    trie: Vec<TrieNode>,
}

impl Default for SensitiveFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SensitiveFilter {
    /// 创建空的过滤器实例。
    ///
    /// # 返回值
    /// 包含一个根节点的SensitiveFilter实例。
    pub fn new() -> Self {
        Self {
            trie: vec![TrieNode::default()],
        }
    }

    /// 用词库构建自动机。
    ///
    /// # 参数
    /// * `words` - 敏感词列表切片
    pub fn build(&mut self, words: &[String]) {
        self.trie = vec![TrieNode::default()];
        for word in words {
            if !word.is_empty() {
                self.insert(word);
            }
        }
        self.build_failure_links();
    }

    fn insert(&mut self, word: &str) {
        let mut node_idx = 0;
        for ch in word.chars() {
            let next_idx = self.trie[node_idx].children.get(&ch).copied();
            match next_idx {
                Some(idx) => {
                    node_idx = idx;
                }
                None => {
                    let new_idx = self.trie.len();
                    self.trie.push(TrieNode::default());
                    self.trie[node_idx].children.insert(ch, new_idx);
                    node_idx = new_idx;
                }
            }
        }
        self.trie[node_idx].outputs.insert(word.to_string());
    }

    fn build_failure_links(&mut self) {
        let mut queue: VecDeque<usize> = VecDeque::new();

        let root_children: Vec<usize> = self.trie[0].children.values().copied().collect();
        for child_idx in root_children {
            self.trie[child_idx].fail_link = 0;
            queue.push_back(child_idx);
        }

        while let Some(current) = queue.pop_front() {
            let current_fail = self.trie[current].fail_link;

            let children: Vec<(char, usize)> = self.trie[current]
                .children
                .iter()
                .map(|(ch, &idx)| (*ch, idx))
                .collect();

            for (ch, child_idx) in children {
                queue.push_back(child_idx);

                let mut fail = current_fail;
                loop {
                    if let Some(&next) = self.trie[fail].children.get(&ch) {
                        self.trie[child_idx].fail_link = next;
                        let fail_outputs = self.trie[next].outputs.clone();
                        self.trie[child_idx].outputs.extend(fail_outputs);
                        break;
                    }
                    if fail == 0 {
                        self.trie[child_idx].fail_link = 0;
                        break;
                    }
                    fail = self.trie[fail].fail_link;
                }
            }
        }
    }

    /// 在文本中搜索敏感词。
    ///
    /// # 参数
    /// * `text` - 待搜索的文本
    ///
    /// # 返回值
    /// 匹配到的敏感词及其位置信息列表。
    pub fn search(&self, text: &str) -> Vec<SensitiveWordMatch> {
        let chars: Vec<char> = text.chars().collect();
        let mut results = Vec::new();
        let mut current = 0usize;

        for (i, ch) in chars.iter().enumerate() {
            current = self.go_to(current, *ch);

            for word in &self.trie[current].outputs {
                let word_len = word.chars().count();
                let start_index = i.saturating_sub(word_len - 1);
                results.push(SensitiveWordMatch {
                    word: word.clone(),
                    start_index,
                    end_index: i,
                });
            }
        }

        results
    }

    /// 快速检查文本是否包含敏感词。
    ///
    /// # 参数
    /// * `text` - 待检查的文本
    ///
    /// # 返回值
    /// 包含敏感词返回true，否则返回false。遇到第一个匹配即返回。
    pub fn has_sensitive_words(&self, text: &str) -> bool {
        let mut current = 0usize;

        for ch in text.chars() {
            current = self.go_to(current, ch);
            if !self.trie[current].outputs.is_empty() {
                return true;
            }
        }

        false
    }

    /// 获取词库中的不重复词总数。
    ///
    /// # 返回值
    /// 词库的不重复敏感词数量。
    pub fn word_count(&self) -> usize {
        let mut all_words: HashSet<&String> = HashSet::new();
        for node in &self.trie {
            all_words.extend(&node.outputs);
        }
        all_words.len()
    }

    fn go_to(&self, current: usize, ch: char) -> usize {
        let mut state = current;
        loop {
            if let Some(&next) = self.trie[state].children.get(&ch) {
                return next;
            }
            if state == 0 {
                return 0;
            }
            state = self.trie[state].fail_link;
        }
    }
}

/// 对文本中的敏感词进行替换。
///
/// # 参数
/// * `text` - 原始文本
/// * `filter` - 已构建的敏感词过滤器
/// * `replacement` - 替换字符
///
/// # 返回值
/// 替换敏感词后的文本。
pub fn filter_text(text: &str, filter: &SensitiveFilter, replacement: char) -> String {
    let matches = filter.search(text);
    let mut chars: Vec<char> = text.chars().collect();

    for m in &matches {
        for idx in m.start_index..=m.end_index {
            if idx < chars.len() {
                chars[idx] = replacement;
            }
        }
    }

    chars.into_iter().collect()
}

/// 检查文本是否包含敏感词。
///
/// # 参数
/// * `text` - 待检查的文本
/// * `filter` - 已构建的敏感词过滤器
///
/// # 返回值
/// Ok(()) 表示不含敏感词，Err(Vec<SensitiveWordMatch>) 返回所有匹配结果。
pub fn check_text(text: &str, filter: &SensitiveFilter) -> Result<(), Vec<SensitiveWordMatch>> {
    let results = filter.search(text);
    if results.is_empty() {
        Ok(())
    } else {
        Err(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_filter() -> SensitiveFilter {
        let words: Vec<String> = vec!["敏感词".to_string(), "广告".to_string(), "违禁".to_string()];
        let mut filter = SensitiveFilter::new();
        filter.build(&words);
        filter
    }

    #[test]
    fn test_search_no_match() {
        let filter = create_test_filter();
        let results = filter.search("这是正常文本");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_single_match() {
        let filter = create_test_filter();
        let results = filter.search("这是敏感词测试");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].word, "敏感词");
    }

    #[test]
    fn test_search_multiple_matches() {
        let filter = create_test_filter();
        let results = filter.search("敏感词和广告都违禁");
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_empty_text() {
        let filter = create_test_filter();
        let results = filter.search("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_has_sensitive_words_true() {
        let filter = create_test_filter();
        assert!(filter.has_sensitive_words("包含敏感词"));
    }

    #[test]
    fn test_has_sensitive_words_false() {
        let filter = create_test_filter();
        assert!(!filter.has_sensitive_words("正常内容"));
    }

    #[test]
    fn test_word_count() {
        let filter = create_test_filter();
        assert_eq!(filter.word_count(), 3);
    }

    #[test]
    fn test_filter_text() {
        let filter = create_test_filter();
        let result = filter_text("这是敏感词和广告内容", &filter, '*');
        assert_eq!(result, "这是***和**内容");
    }

    #[test]
    fn test_check_text_ok() {
        let filter = create_test_filter();
        assert!(check_text("正常文本", &filter).is_ok());
    }

    #[test]
    fn test_check_text_err() {
        let filter = create_test_filter();
        let result = check_text("有敏感词", &filter);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn test_overlapping_words() {
        let words: Vec<String> = vec!["abc".to_string(), "abcd".to_string()];
        let mut filter = SensitiveFilter::new();
        filter.build(&words);
        let results = filter.search("abcdef");
        assert!(results.iter().any(|m| m.word == "abc"));
        assert!(results.iter().any(|m| m.word == "abcd"));
    }

    #[test]
    fn test_build_empty_words() {
        let mut filter = SensitiveFilter::new();
        filter.build(&[] as &[String]);
        assert_eq!(filter.word_count(), 0);
    }

    #[test]
    fn test_build_with_empty_string() {
        let words: Vec<String> = vec!["".to_string(), "test".to_string()];
        let mut filter = SensitiveFilter::new();
        filter.build(&words);
        assert_eq!(filter.word_count(), 1);
    }
}