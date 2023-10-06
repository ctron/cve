use super::state::ConstValue;
use super::*;
use crate::common::Description;
use serde::*;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State;

const STATE_VALUE: &str = "REJECTED";

impl Serialize for State {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(STATE_VALUE)
    }
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(ConstValue(STATE_VALUE))
            .map(|()| State)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub state: State,

    #[serde(flatten)]
    pub common: common::Metadata,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_rejected: Option<Timestamp>,
}

impl Deref for Metadata {
    type Target = common::Metadata;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for Metadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Containers {
    pub cna: CnaContainer,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CnaContainer {
    #[serde(flatten)]
    pub common: common::CnaContainer,

    /// Reasons for rejecting this CVE Record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_reasons: Vec<Description>,

    /// Contains an array of CVE IDs that this CVE ID was rejected in favor of because this CVE ID was assigned to the vulnerabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced_by: Vec<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_metadata() {
        let input = r#"
{
    "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
    "assignerShortName": "mitre",
    "cveId": "CVE-2013-7088",
    "datePublished": "2019-11-15T14:19:48",
    "dateReserved": "2013-12-12T00:00:00",
    "dateUpdated": "2019-11-15T14:19:48",
    "state": "PUBLISHED"
}
"#;
        let _metadata: Metadata = serde_json::from_str(input).unwrap();
    }
}
