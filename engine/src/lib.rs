use std::collections::HashSet;

use adblock::cosmetic_filter_cache::ProceduralOrActionFilter;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
struct Engine(adblock::Engine);

#[pyclass(get_all)]
struct NetworkResult {
    matched: bool,
    filter: Option<String>,
    redirect: Option<String>,
}

#[pyclass(get_all)]
struct CosmeticResources {
    hide_selectors: HashSet<String>,
    exceptions: HashSet<String>,
    generichide: bool,
    style_rules: Vec<(String, String)>,
    injected_script: String,
}

#[pymethods]
impl Engine {
    #[new]
    fn new(py: Python<'_>, lists: Vec<String>) -> Self {
        py.detach(move || {
            // Retain the original rule for logs and blocked-document pages.
            let mut filters = FilterSet::new(true);
            for list in lists {
                filters.add_filter_list(list, ParseOptions::default());
            }
            Self(adblock::Engine::new_with_filter_set(filters))
        })
    }

    fn check_network_urls(
        &self,
        url: &str,
        source_url: &str,
        request_type: &str,
        method: &str,
    ) -> PyResult<NetworkResult> {
        let request = Request::new(url, source_url, request_type, method)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let result = self.0.check_network_request(&request);
        // Deliberately leave rewritten_url out of the proxy-facing result.
        Ok(NetworkResult {
            matched: result.should_block(),
            filter: result.filter.and_then(|rule| rule.raw_line),
            redirect: result.redirect,
        })
    }

    fn url_cosmetic_resources(&self, url: &str) -> CosmeticResources {
        let resources = self.0.url_cosmetic_resources(url);
        let mut style_rules: Vec<_> = resources
            .procedural_actions
            .iter()
            .filter_map(|rule| serde_json::from_str::<ProceduralOrActionFilter>(rule).ok())
            .filter_map(|rule| rule.as_css())
            .collect();
        style_rules.sort_unstable();
        CosmeticResources {
            hide_selectors: resources.hide_selectors,
            exceptions: resources.exceptions,
            generichide: resources.generichide,
            style_rules,
            injected_script: resources.injected_script,
        }
    }

    fn hidden_class_id_selectors(
        &self,
        classes: Vec<String>,
        ids: Vec<String>,
        exceptions: HashSet<String>,
    ) -> Vec<String> {
        self.0.hidden_class_id_selectors(classes, ids, &exceptions)
    }
}

#[pymodule]
fn mitm_adblock_engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Engine>()
}
