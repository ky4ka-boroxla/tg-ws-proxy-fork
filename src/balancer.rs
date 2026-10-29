use std::collections::HashMap;

use parking_lot::Mutex;
use rand::seq::SliceRandom;

const DC_IDS: [i32; 6] = [1, 2, 3, 4, 5, 203];

#[derive(Default)]
struct State {
    domains: Vec<String>,
    dc_to_domain: HashMap<i32, String>,
}

#[derive(Default)]
pub struct Balancer {
    state: Mutex<State>,
}

fn sorted(list: &[String]) -> Vec<&String> {
    let mut items: Vec<&String> = list.iter().collect();
    items.sort();
    items
}

impl Balancer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn domains(&self) -> Vec<String> {
        self.state.lock().domains.clone()
    }

    pub fn update_domains_list(&self, domains: &[String]) {
        let mut state = self.state.lock();
        if sorted(&state.domains) == sorted(domains) {
            return;
        }
        state.domains = domains.to_vec();
        let mut rng = rand::thread_rng();
        let mut mapping = HashMap::new();
        for dc in DC_IDS {
            if let Some(choice) = state.domains.choose(&mut rng) {
                mapping.insert(dc, choice.clone());
            }
        }
        state.dc_to_domain = mapping;
    }

    pub fn update_domain_for_dc(&self, dc: i32, domain: &str) -> bool {
        let mut state = self.state.lock();
        if state.dc_to_domain.get(&dc).map(String::as_str) == Some(domain) {
            return false;
        }
        state.dc_to_domain.insert(dc, domain.to_string());
        true
    }

    pub fn get_domains_for_dc(&self, dc: i32) -> Vec<String> {
        let state = self.state.lock();
        let current = state.dc_to_domain.get(&dc).cloned();
        let mut shuffled = state.domains.clone();
        shuffled.shuffle(&mut rand::thread_rng());
        let mut result = Vec::with_capacity(shuffled.len() + 1);
        if let Some(current) = &current {
            result.push(current.clone());
        }
        result.extend(shuffled.into_iter().filter(|d| Some(d) != current.as_ref()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn current_domain_is_yielded_first_and_all_domains_once() {
        let balancer = Balancer::new();
        balancer.update_domains_list(&list(&["a.com", "b.com", "c.com"]));
        balancer.update_domain_for_dc(2, "b.com");
        assert!(!balancer.update_domain_for_dc(2, "b.com"));
        assert!(balancer.update_domain_for_dc(2, "c.com"));
        assert!(balancer.update_domain_for_dc(2, "b.com"));
        let order = balancer.get_domains_for_dc(2);
        assert_eq!(order[0], "b.com");
        let mut rest = order.clone();
        rest.sort();
        assert_eq!(rest, list(&["a.com", "b.com", "c.com"]));
    }

    #[test]
    fn same_domain_set_keeps_assignments() {
        let balancer = Balancer::new();
        balancer.update_domains_list(&list(&["a.com", "b.com"]));
        balancer.update_domain_for_dc(1, "a.com");
        balancer.update_domains_list(&list(&["b.com", "a.com"]));
        assert_eq!(balancer.get_domains_for_dc(1)[0], "a.com");
    }

    #[test]
    fn every_dc_receives_a_domain_on_update() {
        let balancer = Balancer::new();
        balancer.update_domains_list(&list(&["a.com"]));
        for dc in DC_IDS {
            assert_eq!(balancer.get_domains_for_dc(dc), list(&["a.com"]));
        }
    }

    #[test]
    fn unknown_dc_still_returns_pool() {
        let balancer = Balancer::new();
        balancer.update_domains_list(&list(&["a.com", "b.com"]));
        assert_eq!(balancer.get_domains_for_dc(77).len(), 2);
    }
}
