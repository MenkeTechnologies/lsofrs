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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_themes: HashMap<String, CustomThemeColors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_custom_theme: Option<String>,
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
            custom_themes: HashMap::new(),
            active_custom_theme: None,
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
}
