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
    SakuraDen,
    DataStream,
    NeonNoir,
    ChromeHeart,
    VoidWalker,
    ToxicWaste,
    CyberFrost,
    PlasmaCore,
    SteelNerve,
    DarkSignal,
    GlitchPop,
    HoloShift,
    NightCity,
    LaserGrid,
    QuantumFlux,
    BioHazard,
    Darkwave,
    Megacorp,
    Zaibatsu,
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
        ThemeName::SakuraDen,
        ThemeName::DataStream,
        ThemeName::NeonNoir,
        ThemeName::ChromeHeart,
        ThemeName::VoidWalker,
        ThemeName::ToxicWaste,
        ThemeName::CyberFrost,
        ThemeName::PlasmaCore,
        ThemeName::SteelNerve,
        ThemeName::DarkSignal,
        ThemeName::GlitchPop,
        ThemeName::HoloShift,
        ThemeName::NightCity,
        ThemeName::LaserGrid,
        ThemeName::QuantumFlux,
        ThemeName::BioHazard,
        ThemeName::Darkwave,
        ThemeName::Megacorp,
        ThemeName::Zaibatsu,
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
            Self::SakuraDen => "Sakura Den",
            Self::DataStream => "Data Stream",
            Self::NeonNoir => "Neon Noir",
            Self::ChromeHeart => "Chrome Heart",
            Self::VoidWalker => "Void Walker",
            Self::ToxicWaste => "Toxic Waste",
            Self::CyberFrost => "Cyber Frost",
            Self::PlasmaCore => "Plasma Core",
            Self::SteelNerve => "Steel Nerve",
            Self::DarkSignal => "Dark Signal",
            Self::GlitchPop => "Glitch Pop",
            Self::HoloShift => "Holo Shift",
            Self::NightCity => "Night City",
            Self::LaserGrid => "Laser Grid",
            Self::QuantumFlux => "Quantum Flux",
            Self::BioHazard => "Bio Hazard",
            Self::Darkwave => "Darkwave",
            Self::Megacorp => "Megacorp",
            Self::Zaibatsu => "Zaibatsu",
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
        match s.to_ascii_lowercase().replace(['-', ' ', '_'], "").as_str() {
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
            "sakuraden" | "sakura" => Self::SakuraDen,
            "datastream" | "data" => Self::DataStream,
            "neonnoir" | "noir" => Self::NeonNoir,
            "chromeheart" | "chrome" => Self::ChromeHeart,
            "voidwalker" | "void" => Self::VoidWalker,
            "toxicwaste" | "toxic" => Self::ToxicWaste,
            "cyberfrost" | "cyber" => Self::CyberFrost,
            "plasmacore" | "plasma" => Self::PlasmaCore,
            "steelnerve" | "steel" => Self::SteelNerve,
            "darksignal" | "signal" => Self::DarkSignal,
            "glitchpop" | "glitch" => Self::GlitchPop,
            "holoshift" | "holo" => Self::HoloShift,
            "nightcity" | "night" => Self::NightCity,
            "lasergrid" | "laser" => Self::LaserGrid,
            "quantumflux" | "quantum" => Self::QuantumFlux,
            "biohazard" | "bio" => Self::BioHazard,
            "darkwave" | "dark" => Self::Darkwave,
            "megacorp" | "mega" => Self::Megacorp,
            "zaibatsu" | "zai" => Self::Zaibatsu,
            _ => Self::NeonSprawl,
        }
    }
}

/// Complete color theme for lsofrs TUI rendering.
#[derive(Debug, Clone)]
pub struct LsofTheme {
    pub name: ThemeName,
    /// Display name for custom themes (None for built-in themes).
    pub custom_name: Option<String>,
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
            ThemeName::SakuraDen => Self::sakura_den(),
            ThemeName::DataStream => Self::data_stream(),
            ThemeName::NeonNoir => Self::neon_noir(),
            ThemeName::ChromeHeart => Self::chrome_heart(),
            ThemeName::VoidWalker => Self::void_walker(),
            ThemeName::ToxicWaste => Self::toxic_waste(),
            ThemeName::CyberFrost => Self::cyber_frost(),
            ThemeName::PlasmaCore => Self::plasma_core(),
            ThemeName::SteelNerve => Self::steel_nerve(),
            ThemeName::DarkSignal => Self::dark_signal(),
            ThemeName::GlitchPop => Self::glitch_pop(),
            ThemeName::HoloShift => Self::holo_shift(),
            ThemeName::NightCity => Self::night_city(),
            ThemeName::LaserGrid => Self::laser_grid(),
            ThemeName::QuantumFlux => Self::quantum_flux(),
            ThemeName::BioHazard => Self::bio_hazard(),
            ThemeName::Darkwave => Self::darkwave(),
            ThemeName::Megacorp => Self::megacorp(),
            ThemeName::Zaibatsu => Self::zaibatsu(),
        }
    }

    /// Display name, using custom_name if set, otherwise the built-in ThemeName.
    pub fn display_name(&self) -> &str {
        if let Some(ref n) = self.custom_name {
            n.as_str()
        } else {
            self.name.display_name()
        }
    }

    /// Build a theme from a raw 6-color palette with a custom display name.
    pub fn from_custom(custom_name: &str, c1: u8, c2: u8, c3: u8, c4: u8, c5: u8, c6: u8) -> Self {
        let mut t = Self::from_palette(ThemeName::NeonSprawl, c1, c2, c3, c4, c5, c6);
        t.custom_name = Some(custom_name.to_string());
        t
    }

    /// Build a theme from a 6-color palette (c1=primary, c2=accent, c3-c6=secondary).
    fn from_palette(name: ThemeName, c1: u8, c2: u8, c3: u8, c4: u8, c5: u8, c6: u8) -> Self {
        Self {
            name,
            custom_name: None,
            header_bg: Color::Indexed(234),
            header_fg: Color::Indexed(c2),
            pid_fg: Color::Indexed(c1),
            user_fg: Color::Indexed(c2),
            cmd_fg: Color::Indexed(c4),
            fd_fg: Color::Indexed(c3),
            type_fg: Color::Indexed(c5),
            bar_reg: Color::Indexed(c1),
            bar_sock: Color::Indexed(c2),
            bar_pipe: Color::Indexed(c4),
            bar_other: Color::Indexed(c6),
            help_bg: Color::Indexed(236),
            help_border: Color::Indexed(c1),
            help_title: Color::Indexed(c2),
            help_key: Color::Indexed(c3),
            help_val: Color::Indexed(c4),
            delta_plus: Color::Indexed(196),
            delta_minus: Color::Indexed(c3),
            delta_stable: Color::Indexed(c6),
            select_bg: Color::Indexed(237),
            dim_fg: Color::Indexed(240),
            row_alt_bg: Color::Indexed(233),
            bold_fg: Color::Indexed(255),
            section_fg: Color::Indexed(c2),
            legend_fg: Color::Indexed(240),
        }
    }

    /// Cyberpunk: cyan/magenta/green
    fn neon_sprawl() -> Self {
        Self {
            name: ThemeName::NeonSprawl,
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
            header_bg: Color::Indexed(52),
            header_fg: Color::Indexed(226),
            pid_fg: Color::Indexed(208),
            user_fg: Color::Indexed(226),
            cmd_fg: Color::Indexed(214),
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
            custom_name: None,
            header_bg: Color::Indexed(17),
            header_fg: Color::Indexed(159),
            pid_fg: Color::Indexed(75),
            user_fg: Color::Indexed(81),
            cmd_fg: Color::Indexed(123),
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
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
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
            custom_name: None,
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

    // ── New themes ────────────────────────────────────────────────────────────

    /// Cherry blossom: pink/rose
    fn sakura_den() -> Self {
        Self::from_palette(ThemeName::SakuraDen, 175, 218, 182, 225, 169, 132)
    }

    /// Green data terminal
    fn data_stream() -> Self {
        Self::from_palette(ThemeName::DataStream, 22, 46, 28, 119, 34, 22)
    }

    /// Dark neon: magenta/white contrasts
    fn neon_noir() -> Self {
        Self::from_palette(ThemeName::NeonNoir, 201, 231, 93, 219, 57, 53)
    }

    /// Monochrome silver
    fn chrome_heart() -> Self {
        Self::from_palette(ThemeName::ChromeHeart, 250, 255, 246, 253, 243, 239)
    }

    /// Deep purple void
    fn void_walker() -> Self {
        Self::from_palette(ThemeName::VoidWalker, 55, 99, 54, 141, 92, 17)
    }

    /// Neon green/yellow toxic
    fn toxic_waste() -> Self {
        Self::from_palette(ThemeName::ToxicWaste, 118, 190, 154, 226, 82, 58)
    }

    /// Icy blue/white frost
    fn cyber_frost() -> Self {
        Self::from_palette(ThemeName::CyberFrost, 159, 195, 153, 189, 111, 67)
    }

    /// Hot pink/magenta plasma
    fn plasma_core() -> Self {
        Self::from_palette(ThemeName::PlasmaCore, 199, 213, 163, 207, 126, 89)
    }

    /// Steel blue industrial
    fn steel_nerve() -> Self {
        Self::from_palette(ThemeName::SteelNerve, 68, 110, 60, 146, 24, 236)
    }

    /// Very dark teal/green
    fn dark_signal() -> Self {
        Self::from_palette(ThemeName::DarkSignal, 30, 43, 23, 79, 29, 16)
    }

    /// Loud neon multi-color
    fn glitch_pop() -> Self {
        Self::from_palette(ThemeName::GlitchPop, 201, 51, 226, 47, 196, 21)
    }

    /// Holographic cyan/pink
    fn holo_shift() -> Self {
        Self::from_palette(ThemeName::HoloShift, 123, 219, 159, 183, 87, 133)
    }

    /// Warm amber city lights
    fn night_city() -> Self {
        Self::from_palette(ThemeName::NightCity, 214, 227, 209, 223, 172, 94)
    }

    /// Bright neon grid
    fn laser_grid() -> Self {
        Self::from_palette(ThemeName::LaserGrid, 46, 201, 51, 226, 196, 21)
    }

    /// Purple/blue quantum
    fn quantum_flux() -> Self {
        Self::from_palette(ThemeName::QuantumFlux, 135, 75, 171, 111, 98, 61)
    }

    /// Warning green/yellow
    fn bio_hazard() -> Self {
        Self::from_palette(ThemeName::BioHazard, 148, 184, 106, 192, 64, 22)
    }

    /// Dark purple/magenta wave
    fn darkwave() -> Self {
        Self::from_palette(ThemeName::Darkwave, 53, 140, 89, 176, 127, 52)
    }

    /// Corporate gray/blue
    fn megacorp() -> Self {
        Self::from_palette(ThemeName::Megacorp, 252, 39, 245, 81, 242, 236)
    }

    /// Red/orange corporate dystopia
    fn zaibatsu() -> Self {
        Self::from_palette(ThemeName::Zaibatsu, 167, 216, 131, 224, 95, 52)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_themes_count() {
        assert_eq!(ThemeName::ALL.len(), 31);
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
        // New themes
        assert_eq!(ThemeName::from_str_loose("sakura"), ThemeName::SakuraDen);
        assert_eq!(
            ThemeName::from_str_loose("glitch-pop"),
            ThemeName::GlitchPop
        );
        assert_eq!(ThemeName::from_str_loose("zaibatsu"), ThemeName::Zaibatsu);
        assert_eq!(ThemeName::from_str_loose("megacorp"), ThemeName::Megacorp);
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

    #[test]
    fn swatch_colors_six() {
        for &name in ThemeName::ALL {
            let s = name.swatch_colors();
            assert_eq!(s.len(), 6);
        }
    }
}
