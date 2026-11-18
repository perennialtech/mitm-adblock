use std::collections::HashSet;

use adblock::cosmetic_filter_cache::ProceduralOrActionFilter;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
struct Engine {
    inner: adblock::Engine,
    threat_domains: HashSet<String>,
}

#[pyclass(get_all)]
struct NetworkResult {
    matched: bool,
    excepted: bool,
    filter: Option<String>,
    redirect: Option<String>,
}

#[pyclass(get_all)]
struct CosmeticResources {
    hide_selectors: HashSet<String>,
    exceptions: HashSet<String>,
    generichide: bool,
    style_rules: Vec<(String, String)>,
}

#[pymethods]
impl Engine {
    #[new]
    #[pyo3(signature = (lists, threat_domains=None))]
    fn new(py: Python<'_>, lists: Vec<String>, threat_domains: Option<HashSet<String>>) -> Self {
        py.detach(move || {
            // Retain the original rule for logs and blocked-document pages.
            let mut filters = FilterSet::new(true);
            for list in lists {
                filters.add_filter_list(list, ParseOptions::default());
            }
            Self {
                inner: adblock::Engine::new_with_filter_set(filters),
                threat_domains: threat_domains.unwrap_or_default(),
            }
        })
    }

    #[pyo3(signature = (url, source_url, request_type, method, exact_payload_url=false, check_exceptions=false))]
    fn check_network_urls(
        &self,
        url: &str,
        source_url: &str,
        request_type: &str,
        method: &str,
        exact_payload_url: bool,
        check_exceptions: bool,
    ) -> PyResult<NetworkResult> {
        let request = Request::new(url, source_url, request_type, method)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let found_host = self
            .threat_domains
            .contains(request.hostname.trim_end_matches('.'));
        // An exact threat match is an ordinary blocking rule. Evaluate its
        // exceptions and important rules in the same engine.
        let result = self.inner.check_network_request_subset(
            &request,
            found_host || exact_payload_url,
            check_exceptions,
        );
        let matched = result.should_block();
        let excepted = result.exception.is_some();
        let filter = result.filter.and_then(|rule| rule.raw_line).or_else(|| {
            if !matched {
                None
            } else if exact_payload_url {
                Some("Exact threat payload URL".to_owned())
            } else {
                found_host.then(|| "Exact threat hostname".to_owned())
            }
        });
        // Deliberately leave rewritten_url out of the proxy-facing result.
        Ok(NetworkResult {
            matched,
            excepted,
            filter,
            redirect: result.redirect,
        })
    }

    fn url_cosmetic_resources(&self, url: &str) -> CosmeticResources {
        let resources = self.inner.url_cosmetic_resources(url);
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
        }
    }

    fn hidden_class_id_selectors(
        &self,
        classes: Vec<String>,
        ids: Vec<String>,
        exceptions: HashSet<String>,
    ) -> Vec<String> {
        self.inner
            .hidden_class_id_selectors(classes, ids, &exceptions)
    }
}

#[pymodule]
fn mitm_adblock_engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Engine>()
}
