//! Transmutes SysEnumMon events to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::Event;
use bombini_common::event::sysenum::ChainItemType;

use serde::Serialize;

use super::{
    Transmuter, cache::process::ProcessCache, process::Process, str_from_bytes, transmute_ktime,
};

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ChainEntryType {
    Exec { binary: String },
    FileOpen { path: String },
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChainEntry {
    pub entry: ChainEntryType,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SysEnumMonEvent {
    pub process: Arc<Process>,
    pub chain: Vec<ChainEntry>,
    pub timestamp: String,
}

impl SysEnumMonEvent {
    pub fn new(process: Arc<Process>, chain: Vec<ChainEntry>, ktime: u64) -> Self {
        Self {
            process,
            chain,
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct SysEnumMonEventTransmuter;

impl Transmuter for SysEnumMonEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let Event::SysEnum(event) = event else {
            return Err(anyhow!("Unexpected event variant"));
        };
        let process = process_cache
            .get(&event.process)
            .ok_or_else(|| anyhow!("parent process is not in cache"))?
            .process
            .clone();
        let chain_len = (event.chain_len as usize).min(event.chain.len());
        let chain = event
            .chain
            .iter()
            .take(chain_len)
            .map(|item| {
                let entry = match item.entry {
                    ChainItemType::Exec(name) => ChainEntryType::Exec {
                        binary: str_from_bytes(&name),
                    },
                    ChainItemType::FileOpen(path) => ChainEntryType::FileOpen {
                        path: str_from_bytes(&path),
                    },
                };
                ChainEntry {
                    entry,
                    timestamp: transmute_ktime(item.timestamp_ns),
                }
            })
            .collect();
        let high_level_event = SysEnumMonEvent::new(process, chain, ktime);
        Ok(serde_json::to_vec(&high_level_event)?)
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::SysEnumMonEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_sysenummon_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new().append(true).open(&event_ref).unwrap();
        let _ = writeln!(file, "## SysEnumMon\n\n```json");
        let schema = schemars::schema_for!(SysEnumMonEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
