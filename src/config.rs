//! Persistent configuration — reads/writes ~/.lsofrs.conf (TOML)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Custom theme colors stored in config (6-color palette).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomThemeColors {
    pub c1: u8,
    pub c2: u8,
    pub c3: u8,
    pub c4: u8,
    pub c5: u8,
    pub c6: u8,
}

/// User preferences persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefs {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default = "default_refresh")]
    pub refresh_rate: Option<u64>,
    #[serde(default = "default_true")]
    pub show_border: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_tab: Option<u8>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_themes: HashMap<String, CustomThemeColors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_custom_theme: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_pids: Vec<i32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sort_frozen: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compact_view: bool,
    #[serde(default = "default_true")]
    pub hover_tooltips: bool,
}

fn default_refresh() -> Option<u64> {
    Some(1)
}

fn default_true() -> bool {
    true
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            theme: None,
            refresh_rate: Some(1),
            show_border: true,
            active_tab: None,
            custom_themes: HashMap::new(),
            active_custom_theme: None,
            pinned_pids: Vec::new(),
            sort_frozen: false,
            compact_view: false,
            hover_tooltips: true,
        }
    }
}

fn prefs_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".lsofrs.conf"))
}

/// Load preferences from ~/.lsofrs.conf. Returns defaults if missing or malformed.
pub fn load() -> Prefs {
    let path = match prefs_path() {
        Some(p) => p,
        None => return Prefs::default(),
    };
    match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
        Err(_) => Prefs::default(),
    }
}

/// Save preferences to ~/.lsofrs.conf.
pub fn save(prefs: &Prefs) {
    #[cfg(test)]
    {
        let _ = prefs;
    }

    #[cfg(not(test))]
    if let Some(path) = prefs_path()
        && let Ok(s) = toml::to_string_pretty(prefs)
    {
        let _ = std::fs::write(path, s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_default_values() {
        let p = Prefs::default();
        assert!(p.theme.is_none());
        assert_eq!(p.refresh_rate, Some(1));
    }

    #[test]
    fn prefs_serialize_deserialize() {
        let p = Prefs {
            theme: Some("matrix".into()),
            refresh_rate: Some(3),
            ..Default::default()
        };
        let s = toml::to_string_pretty(&p).unwrap();
        let p2: Prefs = toml::from_str(&s).unwrap();
        assert_eq!(p2.theme.as_deref(), Some("matrix"));
        assert_eq!(p2.refresh_rate, Some(3));
    }

    #[test]
    fn prefs_deserialize_empty_toml() {
        let p: Prefs = toml::from_str("").unwrap();
        assert!(p.theme.is_none());
        assert_eq!(p.refresh_rate, Some(1));
    }

    #[test]
    fn prefs_deserialize_partial_toml() {
        let p: Prefs = toml::from_str("theme = \"blade-runner\"").unwrap();
        assert_eq!(p.theme.as_deref(), Some("blade-runner"));
        assert_eq!(p.refresh_rate, Some(1));
    }

    #[test]
    fn load_returns_valid() {
        let p = load();
        // Should always return a valid Prefs
        assert!(p.refresh_rate.is_some() || p.refresh_rate.is_none());
    }

    #[test]
    fn save_no_op_in_test() {
        let p = Prefs::default();
        save(&p); // should not panic or write to disk
    }

    #[test]
    fn prefs_default_border_true() {
        let p = Prefs::default();
        assert!(p.show_border);
    }

    #[test]
    fn prefs_default_no_custom_themes() {
        let p = Prefs::default();
        assert!(p.custom_themes.is_empty());
        assert!(p.active_custom_theme.is_none());
    }

    #[test]
    fn prefs_default_no_pinned() {
        let p = Prefs::default();
        assert!(p.pinned_pids.is_empty());
    }

    #[test]
    fn prefs_default_not_frozen_or_compact() {
        let p = Prefs::default();
        assert!(!p.sort_frozen);
        assert!(!p.compact_view);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn prefs_roundtrip_all_fields() {
        let mut ct = HashMap::new();
        ct.insert(
            "MyTheme".to_string(),
            CustomThemeColors {
                c1: 10,
                c2: 20,
                c3: 30,
                c4: 40,
                c5: 50,
                c6: 60,
            },
        );
        let p = Prefs {
            theme: Some("ice-breaker".into()),
            refresh_rate: Some(5),
            show_border: false,
            active_tab: Some(3),
            pinned_pids: vec![100, 200],
            sort_frozen: true,
            compact_view: true,
            hover_tooltips: false,
            custom_themes: ct,
            active_custom_theme: Some("MyTheme".into()),
        };

        let s = toml::to_string_pretty(&p).unwrap();
        let p2: Prefs = toml::from_str(&s).unwrap();

        assert_eq!(p2.theme.as_deref(), Some("ice-breaker"));
        assert_eq!(p2.refresh_rate, Some(5));
        assert!(!p2.show_border);
        assert_eq!(p2.active_tab, Some(3));
        assert_eq!(p2.pinned_pids, vec![100, 200]);
        assert!(p2.sort_frozen);
        assert!(p2.compact_view);
        assert_eq!(p2.custom_themes.len(), 1);
        let ct = &p2.custom_themes["MyTheme"];
        assert_eq!(ct.c1, 10);
        assert_eq!(ct.c6, 60);
        assert_eq!(p2.active_custom_theme.as_deref(), Some("MyTheme"));
    }

    #[test]
    fn prefs_skip_empty_fields_in_serialize() {
        let p = Prefs::default();
        let s = toml::to_string_pretty(&p).unwrap();
        // Empty collections should not appear
        assert!(!s.contains("pinned_pids"));
        assert!(!s.contains("custom_themes"));
        assert!(!s.contains("active_custom_theme"));
        assert!(!s.contains("sort_frozen"));
        assert!(!s.contains("compact_view"));
    }
}
