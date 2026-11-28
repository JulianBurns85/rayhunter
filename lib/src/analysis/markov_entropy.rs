use std::collections::HashMap;
use chrono::{DateTime, FixedOffset};

use super::analyzer::{Analyzer, AnalyzerMetadata, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RrcNasState {
    DlCcch,
    DlDcch,
    UlCcch,
    UlDcch,
    BcchBch,
    BcchDlSch,
    Pcch,
    Nas,
    Other,
}

impl RrcNasState {
    fn from_lte_ie(ie: &LteInformationElement) -> Self {
        match ie {
            LteInformationElement::DlCcch(_) => Self::DlCcch,
            LteInformationElement::DlDcch(_) => Self::DlDcch,
            LteInformationElement::UlCcch(_) => Self::UlCcch,
            LteInformationElement::UlDcch(_) => Self::UlDcch,
            LteInformationElement::BcchBch(_) => Self::BcchBch,
            LteInformationElement::BcchDlSch(_) => Self::BcchDlSch,
            LteInformationElement::PCCH(_) => Self::Pcch,
            LteInformationElement::NAS(_) => Self::Nas,
            _ => Self::Other,
        }
    }
}

pub struct MarkovRrcEntropyAnalyzer {
    last_state: Option<RrcNasState>,
    transitions: HashMap<(RrcNasState, RrcNasState), u64>,
    state_counts: HashMap<RrcNasState, u64>,
    total_events: u64,
    entropy_threshold: f64,
    min_observations: u64,
}

impl Default for MarkovRrcEntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkovRrcEntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            last_state: None,
            transitions: HashMap::new(),
            state_counts: HashMap::new(),
            total_events: 0,
            entropy_threshold: 2.50,
            min_observations: 15,
        }
    }

    pub fn shannon_entropy(&self) -> f64 {
        if self.total_events == 0 {
            return 0.0;
        }
        let total = self.total_events as f64;
        self.state_counts
            .values()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = (count as f64) / total;
                -p * p.log2()
            })
            .sum()
    }
}

impl Analyzer for MarkovRrcEntropyAnalyzer {
    fn metadata() -> AnalyzerMetadata {
        AnalyzerMetadata {
            key: "markov_rrc_entropy".into(),
            default_enabled: true,
            name: "Markov RRC Entropy".into(),
            description: "Tracks LTE RRC/NAS state transitions using a Markov chain and Shannon entropy to flag anomalous signaling sequences.".into(),
            version: 1,
        }
    }

    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        _packet_num: usize,
        _timestamp: DateTime<FixedOffset>,
    ) -> Option<Event> {
        let InformationElement::LTE(lte_ie) = ie else {
            return None;
        };

        let state = RrcNasState::from_lte_ie(lte_ie);
        self.total_events += 1;
        *self.state_counts.entry(state).or_insert(0) += 1;

        let prev = match self.last_state.replace(state) {
            Some(p) => p,
            None => return None,
        };

        let edge_count = {
            let entry = self.transitions.entry((prev, state)).or_insert(0);
            *entry += 1;
            *entry
        };

        if self.total_events < self.min_observations {
            return None;
        }

        let entropy = self.shannon_entropy();

        if edge_count == 1 && entropy >= self.entropy_threshold {
            return Some(Event {
                event_type: EventType::Medium,
                message: format!(
                    "Markov RRC/NAS anomaly: unseen transition {:?} -> {:?} (entropy={:.3}, events={})",
                    prev, state, entropy, self.total_events
                ),
            });
        }

        None
    }
}