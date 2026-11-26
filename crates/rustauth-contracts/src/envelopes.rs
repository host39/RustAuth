//! Success envelopes, the same as the RustInit template's: a payload never sits at the JSON root.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// `200` list response: `{ items, total }`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::ListResponse<T>)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    /// Every matching item, not only those on this page.
    pub total: u64,
}

/// `200` or `201` details response: `{ data }`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::DetailsResponse<T>)]
pub struct DetailsResponse<T> {
    pub data: T,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_the_list_envelope() {
        let body = ListResponse {
            items: vec!["a"],
            total: 3,
        };
        assert_eq!(
            serde_json::to_value(body).expect("serializes"),
            serde_json::json!({ "items": ["a"], "total": 3 })
        );
    }

    #[test]
    fn serializes_the_details_envelope() {
        let body = DetailsResponse { data: 7 };
        assert_eq!(
            serde_json::to_value(body).expect("serializes"),
            serde_json::json!({ "data": 7 })
        );
    }
}
