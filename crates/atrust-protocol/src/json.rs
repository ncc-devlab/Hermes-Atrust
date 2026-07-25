use serde::Serialize;
use thiserror::Error;

/// Serializes a typed wire DTO without pretty printing or intermediate maps.
///
/// aTrust signs the exact JSON bytes. Wire DTOs must therefore be structs with fields declared in
/// protocol order. Callers must not use maps whose key ordering can differ from the peer.
pub fn to_wire_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolJsonError> {
    serde_json::to_vec(value).map_err(ProtocolJsonError::Serialize)
}

#[derive(Debug, Error)]
pub enum ProtocolJsonError {
    #[error("failed to serialize aTrust wire JSON: {0}")]
    Serialize(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct UnsignedRequest<'a> {
        sid: &'a str,
        app_id: &'a str,
        x_request_sig: &'a str,
    }

    #[test]
    fn wire_json_is_compact_and_keeps_struct_field_order() {
        let request = UnsignedRequest {
            sid: "sid-value",
            app_id: "app-value",
            x_request_sig: "",
        };
        assert_eq!(
            to_wire_json(&request).unwrap(),
            br#"{"sid":"sid-value","appId":"app-value","xRequestSig":""}"#
        );
    }

    #[test]
    fn wire_json_escapes_untrusted_strings() {
        let request = UnsignedRequest {
            sid: "quote\"and\\slash",
            app_id: "app",
            x_request_sig: "",
        };
        assert_eq!(
            to_wire_json(&request).unwrap(),
            br#"{"sid":"quote\"and\\slash","appId":"app","xRequestSig":""}"#
        );
    }
}
