//! Color theme system for the ratatui TUI
//!
//! Defines `LsofTheme` with named color fields using `Color::Indexed(u8)`,
//! and preset themes selectable by `ThemeName`.

use ratatui::style::Color;

/// All named color themes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeName {
    #[default]
    NeonSprawl,
    Classic,
    SolarFlare,
    IceBreaker,
    Matrix,
}

impl ThemeName {
    pub const ALL: &'static [ThemeName] = &[
        ThemeName::NeonSprawl,
        ThemeName::Classic,
        ThemeName::SolarFlare,
        ThemeName::IceBreaker,
        ThemeName::Matrix,
    ];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::NeonSprawl => "Neon Sprawl",
            Self::Classic => "Classic",
            Self::SolarFlare => "Solar Flare",
            Self::IceBreaker => "Ice Breaker",
            Self::Matrix => "Matrix",
        }
    }

    /// Parse from CLI string (case-insensitive, dashes optional).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().replace('-', "").as_str() {
            "neonsprawl" | "neon" => Self::NeonSprawl,
            "classic" | "plain" => Self::Classic,
            "solarflare" | "solar" => Self::SolarFlare,
            "icebreaker" | "ice" => Self::IceBreaker,
            "matrix" | "green" => Self::Matrix,
            _ => Self::NeonSprawl,
        }
    }
}

/// Complete color theme for lsofrs TUI rendering.
#[derive(Debug, Clone)]
pub struct LsofTheme {
    pub name: ThemeName,
    // Header/title bar
    pub header_bg: Color,
    pub header_fg: Color,
    // Column colors
    pub pid_fg: Color,
    pub user_fg: Color,
    pub cmd_fg: Color,
    pub fd_fg: Color,
    pub type_fg: Color,
    // Distribution bar colors
    pub bar_reg: Color,
    pub bar_sock: Color,
    pub bar_pipe: Color,
    pub bar_other: Color,
    // Help overlay
    pub help_bg: Color,
    pub help_border: Color,
    pub help_title: Color,
    pub help_key: Color,
    pub help_val: Color,
    // Delta indicators
    pub delta_plus: Color,
    pub delta_minus: Color,
    pub delta_stable: Color,
    // Selection highlight
    pub select_bg: Color,
    // Dim/secondary text
    pub dim_fg: Color,
    // Row alternate background
    pub row_alt_bg: Color,
    // Bold text (for counts/numbers)
    pub bold_fg: Color,
    // Section headers
    pub section_fg: Color,
    // Legend text
    pub legend_fg: Color,
}

impl LsofTheme {
    pub fn from_name(name: ThemeName) -> Self {
        match name {
            ThemeName::NeonSprawl => Self::neon_sprawl(),
            ThemeName::Classic => Self::classic(),
            ThemeName::SolarFlare => Self::solar_flare(),
            ThemeName::IceBreaker => Self::ice_breaker(),
            ThemeName::Matrix => Self::matrix(),
        }
    }

    /// Cyberpunk: cyan/magenta/green
    fn neon_sprawl() -> Self {
        Self {
            name: ThemeName::NeonSprawl,
            header_bg: Color::Indexed(234),
            header_fg: Color::Indexed(255),
            pid_fg: Color::Indexed(201),  // magenta
            user_fg: Color::Indexed(226), // yellow
            cmd_fg: Color::Indexed(51),   // cyan
            fd_fg: Color::Indexed(48),    // green
            type_fg: Color::Indexed(75),  // blue
            bar_reg: Color::Indexed(51),
            bar_sock: Color::Indexed(48),
            bar_pipe: Color::Indexed(226),
            bar_other: Color::Indexed(240),
            help_bg: Color::Indexed(236),
            help_border: Color::Indexed(51),
            help_title: Color::Indexed(201),
            help_key: Color::Indexed(48),
            help_val: Color::Indexed(252),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(48),
            delta_stable: Color::Indexed(240),
            select_bg: Color::Indexed(236),
            dim_fg: Color::Indexed(240),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(255),
            section_fg: Color::Indexed(255),
            legend_fg: Color::Indexed(240),
        }
    }

    /// Plain lsof-like: white/gray
    fn classic() -> Self {
        Self {
            name: ThemeName::Classic,
            header_bg: Color::Indexed(236),
            header_fg: Color::Indexed(255),
            pid_fg: Color::Indexed(252),
            user_fg: Color::Indexed(252),
            cmd_fg: Color::Indexed(255),
            fd_fg: Color::Indexed(250),
            type_fg: Color::Indexed(248),
            bar_reg: Color::Indexed(252),
            bar_sock: Color::Indexed(248),
            bar_pipe: Color::Indexed(244),
            bar_other: Color::Indexed(240),
            help_bg: Color::Indexed(235),
            help_border: Color::Indexed(250),
            help_title: Color::Indexed(255),
            help_key: Color::Indexed(252),
            help_val: Color::Indexed(248),
            delta_plus: Color::Indexed(255),
            delta_minus: Color::Indexed(248),
            delta_stable: Color::Indexed(240),
            select_bg: Color::Indexed(237),
            dim_fg: Color::Indexed(244),
            row_alt_bg: Color::Indexed(234),
            bold_fg: Color::Indexed(255),
            section_fg: Color::Indexed(255),
            legend_fg: Color::Indexed(244),
        }
    }

    /// Warm: orange/yellow
    fn solar_flare() -> Self {
        Self {
            name: ThemeName::SolarFlare,
            header_bg: Color::Indexed(52),
            header_fg: Color::Indexed(226),
            pid_fg: Color::Indexed(208),  // orange
            user_fg: Color::Indexed(226), // yellow
            cmd_fg: Color::Indexed(214),  // gold
            fd_fg: Color::Indexed(220),
            type_fg: Color::Indexed(172),
            bar_reg: Color::Indexed(208),
            bar_sock: Color::Indexed(214),
            bar_pipe: Color::Indexed(220),
            bar_other: Color::Indexed(94),
            help_bg: Color::Indexed(52),
            help_border: Color::Indexed(208),
            help_title: Color::Indexed(226),
            help_key: Color::Indexed(214),
            help_val: Color::Indexed(180),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(220),
            delta_stable: Color::Indexed(94),
            select_bg: Color::Indexed(52),
            dim_fg: Color::Indexed(94),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(226),
            section_fg: Color::Indexed(226),
            legend_fg: Color::Indexed(94),
        }
    }

    /// Cool: blue/cyan
    fn ice_breaker() -> Self {
        Self {
            name: ThemeName::IceBreaker,
            header_bg: Color::Indexed(17),
            header_fg: Color::Indexed(159),
            pid_fg: Color::Indexed(75),  // blue
            user_fg: Color::Indexed(81), // sky
            cmd_fg: Color::Indexed(123), // bright cyan
            fd_fg: Color::Indexed(117),
            type_fg: Color::Indexed(39),
            bar_reg: Color::Indexed(75),
            bar_sock: Color::Indexed(81),
            bar_pipe: Color::Indexed(123),
            bar_other: Color::Indexed(60),
            help_bg: Color::Indexed(17),
            help_border: Color::Indexed(75),
            help_title: Color::Indexed(159),
            help_key: Color::Indexed(81),
            help_val: Color::Indexed(153),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(81),
            delta_stable: Color::Indexed(60),
            select_bg: Color::Indexed(17),
            dim_fg: Color::Indexed(60),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(159),
            section_fg: Color::Indexed(159),
            legend_fg: Color::Indexed(60),
        }
    }

    /// Green on black
    fn matrix() -> Self {
        Self {
            name: ThemeName::Matrix,
            header_bg: Color::Indexed(22),
            header_fg: Color::Indexed(46),
            pid_fg: Color::Indexed(40),
            user_fg: Color::Indexed(34),
            cmd_fg: Color::Indexed(46),
            fd_fg: Color::Indexed(40),
            type_fg: Color::Indexed(28),
            bar_reg: Color::Indexed(46),
            bar_sock: Color::Indexed(40),
            bar_pipe: Color::Indexed(34),
            bar_other: Color::Indexed(22),
            help_bg: Color::Indexed(22),
            help_border: Color::Indexed(46),
            help_title: Color::Indexed(46),
            help_key: Color::Indexed(40),
            help_val: Color::Indexed(34),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(40),
            delta_stable: Color::Indexed(22),
            select_bg: Color::Indexed(22),
            dim_fg: Color::Indexed(22),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(46),
            section_fg: Color::Indexed(46),
            legend_fg: Color::Indexed(22),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_themes_count() {
        assert_eq!(ThemeName::ALL.len(), 5);
    }

    #[test]
    fn default_is_neon_sprawl() {
        assert_eq!(ThemeName::default(), ThemeName::NeonSprawl);
    }

    #[test]
    fn all_themes_have_display_names() {
        for &name in ThemeName::ALL {
            assert!(!name.display_name().is_empty());
        }
    }

    #[test]
    fn all_themes_produce_valid_theme() {
        for &name in ThemeName::ALL {
            let t = LsofTheme::from_name(name);
            assert_eq!(t.name, name);
        }
    }

    #[test]
    fn all_themes_unique_display_names() {
        let mut names: Vec<&str> = ThemeName::ALL.iter().map(|t| t.display_name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), ThemeName::ALL.len());
    }

    #[test]
    fn from_str_loose_parses() {
        assert_eq!(
            ThemeName::from_str_loose("neon-sprawl"),
            ThemeName::NeonSprawl
        );
        assert_eq!(ThemeName::from_str_loose("CLASSIC"), ThemeName::Classic);
        assert_eq!(
            ThemeName::from_str_loose("solar-flare"),
            ThemeName::SolarFlare
        );
        assert_eq!(
            ThemeName::from_str_loose("ice-breaker"),
            ThemeName::IceBreaker
        );
        assert_eq!(ThemeName::from_str_loose("matrix"), ThemeName::Matrix);
        assert_eq!(ThemeName::from_str_loose("unknown"), ThemeName::NeonSprawl);
    }

    #[test]
    fn neon_sprawl_colors() {
        let t = LsofTheme::from_name(ThemeName::NeonSprawl);
        assert!(matches!(t.header_bg, Color::Indexed(234)));
        assert!(matches!(t.pid_fg, Color::Indexed(201)));
        assert!(matches!(t.cmd_fg, Color::Indexed(51)));
    }

    #[test]
    fn theme_clone() {
        let t = LsofTheme::from_name(ThemeName::Matrix);
        let t2 = t.clone();
        assert_eq!(t.name, t2.name);
        assert_eq!(t.header_bg, t2.header_bg);
    }
}
