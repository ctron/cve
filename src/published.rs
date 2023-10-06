use super::state::ConstValue;
use super::*;
use crate::common::{Description, ProblemType, Product};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State;

const STATE_VALUE: &str = "PUBLISHED";

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

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adp: Vec<AdpContainer>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CnaContainer {
    #[serde(flatten)]
    pub common: common::CnaContainer,

    /// The date/time this CVE ID was associated with a vulnerability by a CNA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_assigned: Option<Timestamp>,

    /// If known, the date/time the vulnerability was disclosed publicly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_public: Option<Timestamp>,

    /// A title, headline, or a brief phrase summarizing the CVE record. Eg., Buffer overflow in Example Soft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// A list of multi-lingual descriptions of the vulnerability. E.g., [PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] on [PLATFORMS] allows [ATTACKER] to [IMPACT] via [VECTOR]. OR [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] [ROOT CAUSE], which allows [ATTACKER] to [IMPACT] via [VECTOR].
    pub descriptions: Vec<Description>,

    /// List of affected products.
    pub affected: Vec<Product>,

    /// This is problem type information (e.g. CWE identifier). Must contain: At least one entry, can be text, OWASP, CWE, please note that while only one is required you can use more than one (or indeed all three) as long as they are correct). (CNA requirement: [PROBLEMTYPE]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problem_types: Vec<ProblemType>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdpContainer {}

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
