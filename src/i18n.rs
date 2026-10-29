use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::En => "en",
        }
    }

    pub fn parse(value: &str) -> Lang {
        match value.trim().to_lowercase().as_str() {
            "ru" => Lang::Ru,
            _ => Lang::En,
        }
    }

    pub fn all() -> [Lang; 2] {
        [Lang::Ru, Lang::En]
    }
}

const RU_JSON: &str = include_str!("../i18n/ru.json");
const EN_JSON: &str = include_str!("../i18n/en.json");

fn catalog(lang: Lang) -> &'static HashMap<String, String> {
    static RU: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| serde_json::from_str(RU_JSON).expect("ru.json"));
    static EN: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| serde_json::from_str(EN_JSON).expect("en.json"));
    match lang {
        Lang::Ru => &RU,
        Lang::En => &EN,
    }
}

static CURRENT: RwLock<Lang> = RwLock::new(Lang::En);

pub fn set_language(lang: Lang) {
    if let Ok(mut current) = CURRENT.write() {
        *current = lang;
    }
}

pub fn language() -> Lang {
    CURRENT.read().map(|l| *l).unwrap_or(Lang::En)
}

pub fn translate(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    let template = catalog(lang)
        .get(key)
        .or_else(|| catalog(Lang::En).get(key))
        .map(String::as_str)
        .unwrap_or(key);
    let mut out = template.to_string();
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

pub fn t(key: &str) -> String {
    translate(language(), key, &[])
}

pub fn tf(key: &str, args: &[(&str, &str)]) -> String {
    translate(language(), key, args)
}

pub fn keys(lang: Lang) -> Vec<&'static String> {
    catalog(lang).keys().collect()
}

pub fn detect_system_language() -> Lang {
    #[cfg(windows)]
    {
        let mut buffer = [0u16; 85];
        let len = unsafe {
            windows_sys::Win32::Globalization::GetUserDefaultLocaleName(buffer.as_mut_ptr(), buffer.len() as i32)
        };
        if len > 0 {
            let name = String::from_utf16_lossy(&buffer[..(len as usize).saturating_sub(1)]);
            let code = name.split(['-', '_']).next().unwrap_or("").to_lowercase();
            return Lang::parse(&code);
        }
    }
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                let code = value.split('.').next().unwrap_or("").split('_').next().unwrap_or("");
                if code.eq_ignore_ascii_case("ru") {
                    return Lang::Ru;
                }
                if code.eq_ignore_ascii_case("en") {
                    return Lang::En;
                }
            }
        }
    }
    Lang::En
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn placeholders(text: &str) -> BTreeSet<String> {
        let mut found = BTreeSet::new();
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            let Some(end) = rest[start..].find('}') else { break };
            found.insert(rest[start + 1..start + end].to_string());
            rest = &rest[start + end + 1..];
        }
        found
    }

    #[test]
    fn catalogs_have_identical_keys() {
        let ru: BTreeSet<_> = keys(Lang::Ru).into_iter().collect();
        let en: BTreeSet<_> = keys(Lang::En).into_iter().collect();
        assert_eq!(ru, en);
        assert!(en.len() > 100);
    }

    #[test]
    fn placeholders_match_between_languages() {
        for key in keys(Lang::En) {
            let ru = catalog(Lang::Ru).get(key).unwrap();
            let en = catalog(Lang::En).get(key).unwrap();
            assert_eq!(placeholders(ru), placeholders(en), "{key}");
        }
    }

    #[test]
    fn translate_substitutes_arguments_and_falls_back_to_key() {
        assert_eq!(
            translate(Lang::En, "connectivity.available", &[("title", "CF Proxy")]),
            "CF Proxy: available"
        );
        assert_eq!(translate(Lang::En, "no.such.key", &[]), "no.such.key");
        assert!(translate(Lang::Ru, "app.name", &[]).len() > 0);
    }

    #[test]
    fn parse_language_codes() {
        assert_eq!(Lang::parse("ru"), Lang::Ru);
        assert_eq!(Lang::parse(" RU "), Lang::Ru);
        assert_eq!(Lang::parse("xx"), Lang::En);
        assert_eq!(Lang::Ru.code(), "ru");
    }

    #[test]
    fn every_catalog_value_is_nonempty() {
        for lang in Lang::all() {
            for (key, value) in catalog(lang) {
                assert!(!value.is_empty(), "{key}");
            }
        }
    }
}
