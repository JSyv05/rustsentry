//! Weeks 9-11: ML-based flow classifier — the project's AI component.
//!
//! Turns flow-level state (packet rate, distinct-port count, SYN/ACK ratio,
//! etc.) into a feature vector, runs it through a trained `linfa` model, and
//! emits Alerts for anything classified as an attack pattern.
//!
//! This module intentionally mirrors the interface of syn_flood/port_scan
//! (`check(...) -> Vec<Alert>`) so it plugs into the same pipeline without
//! special-casing in `cli`.
//!
//! Training happens offline (a separate binary/script, not at runtime) —
//! see `train_model()` below for where that lives. The runtime path here
//! only ever *loads* an already-trained model and does inference.

use crate::{Alert, AlertKind};
use flow::SlidingWindowCounters;
use ndarray::Array1;

/// One row of the feature vector fed to the model. Field order must match
/// whatever order the model was trained on — keep this struct and the
/// training pipeline's feature extraction in sync (week 9 task: decide the
/// exact feature set based on what your chosen dataset provides).
#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub packets_per_sec: f64,
    pub syn_ack_ratio: f64,
    pub distinct_dst_ports: f64,
    pub avg_payload_len: f64,
    // TODO(week 9): extend to match dataset columns (CICIDS2017/NSL-KDD/UNSW-NB15
    // all expose slightly different feature sets — pick one and align here)
}

impl FlowFeatures {
    /// TODO(week 9): extract this from flow::SlidingWindowCounters's
    /// per-key window state (may require exposing more fields from `flow`
    /// than it currently does — that's expected, extend WindowState as needed).
    pub fn to_array(&self) -> Array1<f64> {
        Array1::from(vec![
            self.packets_per_sec,
            self.syn_ack_ratio,
            self.distinct_dst_ports,
            self.avg_payload_len,
        ])
    }
}

/// Wraps a trained linfa model. Which concrete model type this holds
/// (DecisionTree vs. logistic regression, etc.) depends on what you land on
/// in week 10 — start with linfa_trees::DecisionTree since it's easy to
/// inspect/explain in your writeup, swap later if needed.
pub struct MlClassifier {
    // TODO(week 10): store the trained linfa model here, e.g.
    // model: linfa_trees::DecisionTree<f64, usize>,
}

impl MlClassifier {
    /// TODO(week 11): load a serialized trained model from disk
    /// (linfa models can be serialized via serde if the `serde` feature
    /// is enabled on the relevant linfa crate).
    pub fn load(_model_path: &str) -> anyhow::Result<Self> {
        todo!("load trained model — week 11")
    }

    /// TODO(week 11): run inference on extracted features, map the
    /// predicted class back to an AlertKind, emit an Alert if the
    /// predicted class isn't "benign".
    pub fn check(&self, _counters: &SlidingWindowCounters) -> Vec<Alert> {
        todo!("ML inference over current flow state — week 11")
    }
}

/// Offline training entry point — NOT called from the live pipeline.
/// Expected to be its own small binary (e.g. `crates/cli/src/bin/train.rs`)
/// or a standalone script, run once against your labeled dataset to produce
/// the serialized model file that `MlClassifier::load()` reads at runtime.
///
/// TODO(week 9-10):
///   1. Load labeled dataset (CICIDS2017/NSL-KDD/UNSW-NB15), parse into
///      FlowFeatures + label pairs.
///   2. Train/validation split.
///   3. Train with linfa_trees::DecisionTree (or linfa_logistic).
///   4. Report precision/recall/F1 on the validation split — this becomes
///      part of your Phase 4 evaluation section.
///   5. Serialize the trained model to disk.
pub fn train_model(_dataset_path: &str, _output_model_path: &str) -> anyhow::Result<()> {
    todo!("offline training pipeline — weeks 9-10")
}
