use dex_parser_rust::{Dex, DexParser};
use std::panic::{AssertUnwindSafe, catch_unwind, set_hook, take_hook};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

static PARSER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn parse_file(path: &Path) -> Result<Dex<'static>, String> {
    let _guard = PARSER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "DEX parser lock poisoned".to_string())?;
    let previous_hook = take_hook();
    set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| DexParser::parse_file(path)));
    set_hook(previous_hook);
    result
        .map_err(|_| String::from("DEX parser panicked on malformed or unsupported input"))?
        .map_err(|error| error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    pub source_class: String,
    pub source_method: String,
    pub target: String,
}

pub fn call_edges(dex: &Dex<'_>) -> Vec<CallEdge> {
    let mut edges = Vec::new();
    for class in &dex.class_defs {
        for method in class
            .direct_methods
            .iter()
            .chain(class.virtual_methods.iter())
        {
            let Some(code) = &method.code else {
                continue;
            };
            for instruction in &code.instructions {
                if instruction.name.starts_with("invoke-")
                    && let Some(target) = instruction.resolved_value.clone()
                {
                    edges.push(CallEdge {
                        source_class: class.name.clone(),
                        source_method: method.name.clone(),
                        target,
                    });
                }
            }
        }
    }
    edges
}

pub fn reachable_library_method(
    dex: &Dex<'_>,
    package_prefix: &str,
    vulnerable_method: Option<&str>,
) -> bool {
    call_edges(dex).iter().any(|edge| {
        let source_is_app = !class_matches_package_prefix(&edge.source_class, package_prefix);
        let target_is_library = class_matches_package_prefix(&edge.target, package_prefix);
        let target_matches = vulnerable_method
            .map(|method| edge.target.contains(method))
            .unwrap_or(false);
        source_is_app && target_is_library && target_matches
    })
}

pub fn class_matches_package_prefix(class_name: &str, package_prefix: &str) -> bool {
    let class_name = class_name.strip_prefix('L').unwrap_or(class_name);
    let class_name = class_name.strip_suffix(';').unwrap_or(class_name);
    let package_prefix = package_prefix.replace('.', "/");
    class_name == package_prefix
        || class_name
            .strip_prefix(&package_prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::class_matches_package_prefix;

    #[test]
    fn matches_dalvik_names_to_dot_separated_package_prefixes() {
        assert!(class_matches_package_prefix(
            "Lcom/google/gson/Gson;",
            "com.google.gson"
        ));
        assert!(class_matches_package_prefix(
            "Lokhttp3/OkHttpClient;",
            "okhttp3"
        ));
        assert!(class_matches_package_prefix(
            "Lretrofit2/Retrofit;",
            "retrofit2"
        ));
        assert!(!class_matches_package_prefix(
            "Lcom/google/gsonish/Gson;",
            "com.google.gson"
        ));
    }
}
