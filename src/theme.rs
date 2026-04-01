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
    BladeRunner,
    Synthwave,
    AcidRain,
    GhostWire,
    RedSector,
    DeepNet,
    Overlock,
}

impl ThemeName {
    pub const ALL: &'static [ThemeName] = &[
        ThemeName::NeonSprawl,
        ThemeName::Classic,
        ThemeName::SolarFlare,
        ThemeName::IceBreaker,
        ThemeName::Matrix,
        ThemeName::BladeRunner,
        ThemeName::Synthwave,
        ThemeName::AcidRain,
        ThemeName::GhostWire,
        ThemeName::RedSector,
        ThemeName::DeepNet,
        ThemeName::Overlock,
    ];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::NeonSprawl => "Neon Sprawl",
            Self::Classic => "Classic",
            Self::SolarFlare => "Solar Flare",
            Self::IceBreaker => "Ice Breaker",
            Self::Matrix => "Matrix",
            Self::BladeRunner => "Blade Runner",
            Self::Synthwave => "Synthwave",
            Self::AcidRain => "Acid Rain",
            Self::GhostWire => "Ghost Wire",
            Self::RedSector => "Red Sector",
            Self::DeepNet => "Deep Net",
            Self::Overlock => "Overlock",
        }
    }

    /// 6-color swatch palette for theme chooser display
    pub fn swatch_colors(self) -> [u8; 6] {
        let t = LsofTheme::from_name(self);
        let idx = |c: Color| match c {
            Color::Indexed(i) => i,
            _ => 255,
        };
        [
            idx(t.pid_fg),
            idx(t.user_fg),
            idx(t.cmd_fg),
            idx(t.bar_reg),
            idx(t.bar_sock),
            idx(t.help_key),
        ]
    }

    /// Parse from CLI string (case-insensitive, dashes optional).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().replace('-', "").as_str() {
            "neonsprawl" | "neon" => Self::NeonSprawl,
            "classic" | "plain" => Self::Classic,
            "solarflare" | "solar" => Self::SolarFlare,
            "icebreaker" | "ice" => Self::IceBreaker,
            "matrix" | "green" => Self::Matrix,
            "bladerunner" | "blade" => Self::BladeRunner,
            "synthwave" | "synth" => Self::Synthwave,
            "acidrain" | "acid" => Self::AcidRain,
            "ghostwire" | "ghost" => Self::GhostWire,
            "redsector" | "red" => Self::RedSector,
            "deepnet" | "deep" => Self::DeepNet,
            "overlock" | "over" => Self::Overlock,
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
            ThemeName::BladeRunner => Self::blade_runner(),
            ThemeName::Synthwave => Self::synthwave(),
            ThemeName::AcidRain => Self::acid_rain(),
            ThemeName::GhostWire => Self::ghost_wire(),
            ThemeName::RedSector => Self::red_sector(),
            ThemeName::DeepNet => Self::deep_net(),
            ThemeName::Overlock => Self::overlock(),
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

    /// Amber/orange noir
    fn blade_runner() -> Self {
        Self {
            name: ThemeName::BladeRunner,
            header_bg: Color::Indexed(52),
            header_fg: Color::Indexed(208),
            pid_fg: Color::Indexed(208),
            user_fg: Color::Indexed(172),
            cmd_fg: Color::Indexed(215),
            fd_fg: Color::Indexed(180),
            type_fg: Color::Indexed(130),
            bar_reg: Color::Indexed(208),
            bar_sock: Color::Indexed(172),
            bar_pipe: Color::Indexed(130),
            bar_other: Color::Indexed(58),
            help_bg: Color::Indexed(52),
            help_border: Color::Indexed(208),
            help_title: Color::Indexed(215),
            help_key: Color::Indexed(208),
            help_val: Color::Indexed(180),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(172),
            delta_stable: Color::Indexed(58),
            select_bg: Color::Indexed(58),
            dim_fg: Color::Indexed(95),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(215),
            section_fg: Color::Indexed(208),
            legend_fg: Color::Indexed(95),
        }
    }

    /// Purple/pink retrowave
    fn synthwave() -> Self {
        Self {
            name: ThemeName::Synthwave,
            header_bg: Color::Indexed(53),
            header_fg: Color::Indexed(213),
            pid_fg: Color::Indexed(213),
            user_fg: Color::Indexed(177),
            cmd_fg: Color::Indexed(219),
            fd_fg: Color::Indexed(183),
            type_fg: Color::Indexed(141),
            bar_reg: Color::Indexed(213),
            bar_sock: Color::Indexed(177),
            bar_pipe: Color::Indexed(141),
            bar_other: Color::Indexed(96),
            help_bg: Color::Indexed(53),
            help_border: Color::Indexed(213),
            help_title: Color::Indexed(219),
            help_key: Color::Indexed(213),
            help_val: Color::Indexed(183),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(177),
            delta_stable: Color::Indexed(96),
            select_bg: Color::Indexed(53),
            dim_fg: Color::Indexed(96),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(219),
            section_fg: Color::Indexed(213),
            legend_fg: Color::Indexed(96),
        }
    }

    /// Toxic green/yellow
    fn acid_rain() -> Self {
        Self {
            name: ThemeName::AcidRain,
            header_bg: Color::Indexed(22),
            header_fg: Color::Indexed(154),
            pid_fg: Color::Indexed(154),
            user_fg: Color::Indexed(190),
            cmd_fg: Color::Indexed(118),
            fd_fg: Color::Indexed(148),
            type_fg: Color::Indexed(106),
            bar_reg: Color::Indexed(154),
            bar_sock: Color::Indexed(118),
            bar_pipe: Color::Indexed(190),
            bar_other: Color::Indexed(58),
            help_bg: Color::Indexed(22),
            help_border: Color::Indexed(154),
            help_title: Color::Indexed(190),
            help_key: Color::Indexed(118),
            help_val: Color::Indexed(148),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(118),
            delta_stable: Color::Indexed(58),
            select_bg: Color::Indexed(22),
            dim_fg: Color::Indexed(58),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(190),
            section_fg: Color::Indexed(154),
            legend_fg: Color::Indexed(58),
        }
    }

    /// Pale gray/silver stealth
    fn ghost_wire() -> Self {
        Self {
            name: ThemeName::GhostWire,
            header_bg: Color::Indexed(235),
            header_fg: Color::Indexed(253),
            pid_fg: Color::Indexed(146),
            user_fg: Color::Indexed(188),
            cmd_fg: Color::Indexed(253),
            fd_fg: Color::Indexed(146),
            type_fg: Color::Indexed(103),
            bar_reg: Color::Indexed(146),
            bar_sock: Color::Indexed(103),
            bar_pipe: Color::Indexed(188),
            bar_other: Color::Indexed(239),
            help_bg: Color::Indexed(235),
            help_border: Color::Indexed(146),
            help_title: Color::Indexed(253),
            help_key: Color::Indexed(146),
            help_val: Color::Indexed(250),
            delta_plus: Color::Indexed(210),
            delta_minus: Color::Indexed(146),
            delta_stable: Color::Indexed(239),
            select_bg: Color::Indexed(237),
            dim_fg: Color::Indexed(241),
            row_alt_bg: Color::Indexed(234),
            bold_fg: Color::Indexed(253),
            section_fg: Color::Indexed(253),
            legend_fg: Color::Indexed(241),
        }
    }

    /// Red/crimson danger
    fn red_sector() -> Self {
        Self {
            name: ThemeName::RedSector,
            header_bg: Color::Indexed(52),
            header_fg: Color::Indexed(196),
            pid_fg: Color::Indexed(196),
            user_fg: Color::Indexed(167),
            cmd_fg: Color::Indexed(210),
            fd_fg: Color::Indexed(174),
            type_fg: Color::Indexed(124),
            bar_reg: Color::Indexed(196),
            bar_sock: Color::Indexed(167),
            bar_pipe: Color::Indexed(210),
            bar_other: Color::Indexed(88),
            help_bg: Color::Indexed(52),
            help_border: Color::Indexed(196),
            help_title: Color::Indexed(210),
            help_key: Color::Indexed(196),
            help_val: Color::Indexed(174),
            delta_plus: Color::Indexed(226),
            delta_minus: Color::Indexed(167),
            delta_stable: Color::Indexed(88),
            select_bg: Color::Indexed(52),
            dim_fg: Color::Indexed(88),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(210),
            section_fg: Color::Indexed(196),
            legend_fg: Color::Indexed(88),
        }
    }

    /// Dark blue deep ocean
    fn deep_net() -> Self {
        Self {
            name: ThemeName::DeepNet,
            header_bg: Color::Indexed(17),
            header_fg: Color::Indexed(69),
            pid_fg: Color::Indexed(69),
            user_fg: Color::Indexed(33),
            cmd_fg: Color::Indexed(111),
            fd_fg: Color::Indexed(75),
            type_fg: Color::Indexed(27),
            bar_reg: Color::Indexed(69),
            bar_sock: Color::Indexed(33),
            bar_pipe: Color::Indexed(111),
            bar_other: Color::Indexed(18),
            help_bg: Color::Indexed(17),
            help_border: Color::Indexed(69),
            help_title: Color::Indexed(111),
            help_key: Color::Indexed(69),
            help_val: Color::Indexed(75),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(33),
            delta_stable: Color::Indexed(18),
            select_bg: Color::Indexed(18),
            dim_fg: Color::Indexed(24),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(111),
            section_fg: Color::Indexed(69),
            legend_fg: Color::Indexed(24),
        }
    }

    /// Industrial gray/teal
    fn overlock() -> Self {
        Self {
            name: ThemeName::Overlock,
            header_bg: Color::Indexed(236),
            header_fg: Color::Indexed(37),
            pid_fg: Color::Indexed(37),
            user_fg: Color::Indexed(73),
            cmd_fg: Color::Indexed(116),
            fd_fg: Color::Indexed(109),
            type_fg: Color::Indexed(30),
            bar_reg: Color::Indexed(37),
            bar_sock: Color::Indexed(73),
            bar_pipe: Color::Indexed(116),
            bar_other: Color::Indexed(239),
            help_bg: Color::Indexed(236),
            help_border: Color::Indexed(37),
            help_title: Color::Indexed(116),
            help_key: Color::Indexed(37),
            help_val: Color::Indexed(109),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(73),
            delta_stable: Color::Indexed(239),
            select_bg: Color::Indexed(237),
            dim_fg: Color::Indexed(241),
            row_alt_bg: Color::Indexed(234),
            bold_fg: Color::Indexed(116),
            section_fg: Color::Indexed(37),
            legend_fg: Color::Indexed(241),
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
        assert_eq!(ThemeName::ALL.len(), 12);
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
