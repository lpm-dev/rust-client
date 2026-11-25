//! Confirms a macOS app's stapled notarization ticket with Apple.
//!
//! Apple's notarization service publishes the ticket it issues for each
//! notarized code directory as a record in a public CloudKit database, named
//! after the code-directory hash. `stapler validate` fetches that record and
//! compares its ticket with the one stapled to the app. This module does the
//! same over HTTPS, because `/usr/bin/stapler` and `xcrun` only run on a Mac
//! with Xcode or the Command Line Tools installed.

use base64::Engine as _;
use lpm_common::LpmError;
use std::time::Duration;

/// The lookup endpoint of Apple's ticket database, which `stapler` and
/// Gatekeeper's online notarization check also query.
pub(super) const TICKET_LOOKUP_URL: &str = "https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup";

/// CloudKit lookups have kept failing for over 20 s at a time, so the checks
/// spread over about two minutes before giving up, as install.sh's do.
pub(super) const RETRY_DELAYS: [Duration; 5] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

/// A ticket record is under 4 KiB; anything far larger isn't one.
const RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// Record errors CloudKit reports for load or outages, which clear up.
const TRANSIENT_SERVER_ERRORS: [&str; 5] = [
    "THROTTLED",
    "TRY_AGAIN_LATER",
    "SERVICE_UNAVAILABLE",
    "INTERNAL_ERROR",
    "ZONE_BUSY",
];

/// What Apple's ticket database said about one code directory.
#[derive(Debug, PartialEq, Eq)]
enum Lookup {
    /// Apple holds this ticket for the code directory.
    Issued(Vec<u8>),
    /// Apple holds no ticket for the code directory: it was never notarized,
    /// or its ticket was revoked.
    NotIssued,
    /// The service answered with an error that asking again won't change.
    Refused(String),
    /// The service gave no usable answer, which it may give later.
    Unavailable(String),
}

/// An HTTP client for ticket lookups. A redirect is an unexpected answer, so
/// none is followed.
pub(super) fn lookup_client() -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| LpmError::Network(format!("failed to create HTTP client: {error}")))
}

/// Confirms that Apple's ticket database holds exactly `stapled_ticket` for
/// the code directory whose SHA-256 hash is `cdhash`.
///
/// While the service gives no usable answer, it is asked again after each of
/// `retry_delays`, and `on_retry` hears of each wait and what the service
/// said first. A ticket that differs from the stapled one, a missing or
/// revoked ticket, and any other refusal fail at once.
pub(super) async fn confirm_stapled_ticket(
    client: &reqwest::Client,
    lookup_url: &str,
    cdhash: &str,
    stapled_ticket: &[u8],
    retry_delays: &[Duration],
    mut on_retry: impl FnMut(Duration, &str),
) -> Result<(), LpmError> {
    let record_name = record_name(cdhash)?;
    let mut retry_delays = retry_delays.iter();
    loop {
        match lookup(client, lookup_url, &record_name).await {
            Lookup::Issued(ticket) if ticket == stapled_ticket => return Ok(()),
            Lookup::Issued(_) => {
                return Err(LpmError::SelfUpdate(
                    "the notarization ticket stapled to the macOS app is not the one Apple issued \
                     for its code"
                        .to_string(),
                ));
            }
            Lookup::NotIssued => {
                return Err(LpmError::SelfUpdate(
                    "Apple has not issued a notarization ticket for the macOS app's code, or has \
                     revoked it"
                        .to_string(),
                ));
            }
            Lookup::Refused(detail) => {
                return Err(LpmError::SelfUpdate(format!(
                    "Apple's notarization service refused to look up the macOS app's ticket \
                     ({detail})"
                )));
            }
            Lookup::Unavailable(detail) => match retry_delays.next() {
                Some(delay) => {
                    on_retry(*delay, &detail);
                    tokio::time::sleep(*delay).await;
                }
                None => {
                    return Err(LpmError::Network(format!(
                        "Apple's notarization service did not answer while checking the macOS \
                         app's ticket ({detail}); try again in a few minutes"
                    )));
                }
            },
        }
    }
}

/// The record holding the ticket for a SHA-256 code directory: `2/`, the
/// digest type (2 is SHA-256), then the hash truncated to 20 bytes.
fn record_name(cdhash: &str) -> Result<String, LpmError> {
    let well_formed = cdhash.len() == 40
        && cdhash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !well_formed {
        return Err(LpmError::SelfUpdate(
            "macOS app signature has a malformed code-directory hash".to_string(),
        ));
    }
    Ok(format!("2/2/{cdhash}"))
}

async fn lookup(client: &reqwest::Client, lookup_url: &str, record_name: &str) -> Lookup {
    let request = serde_json::json!({ "records": [{ "recordName": record_name }] });
    let response = match client
        .post(lookup_url)
        .header("User-Agent", "lpm-cli")
        .json(&request)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Lookup::Unavailable(lpm_http::display_error(&error.without_url()).to_string());
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        return Lookup::Unavailable(format!("HTTP {}", status.as_u16()));
    }
    if status != reqwest::StatusCode::OK {
        return Lookup::Refused(format!("HTTP {}", status.as_u16()));
    }
    match lpm_http::read_body_capped(response, RESPONSE_MAX_BYTES).await {
        Ok(body) => parse_lookup(&body, record_name),
        Err(lpm_http::ResponseBodyError::Read(error)) => {
            Lookup::Unavailable(lpm_http::display_error(&error.without_url()).to_string())
        }
        Err(_) => Lookup::Unavailable("an oversized answer".to_string()),
    }
}

#[derive(serde::Deserialize)]
struct LookupResponse {
    records: Vec<TicketRecord>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TicketRecord {
    record_name: String,
    server_error_code: Option<String>,
    deleted: Option<bool>,
    fields: Option<TicketFields>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TicketFields {
    signed_ticket: Option<BytesField>,
}

#[derive(serde::Deserialize)]
struct BytesField {
    value: String,
}

fn parse_lookup(body: &[u8], record_name: &str) -> Lookup {
    let Ok(LookupResponse { records }) = serde_json::from_slice(body) else {
        return Lookup::Unavailable("an unreadable answer".to_string());
    };
    let [record] = records.as_slice() else {
        return Lookup::Unavailable("an answer about another record".to_string());
    };
    if record.record_name != record_name {
        return Lookup::Unavailable("an answer about another record".to_string());
    }
    if let Some(code) = &record.server_error_code {
        if code == "NOT_FOUND" {
            return Lookup::NotIssued;
        }
        let code = displayable_server_error(code);
        return if TRANSIENT_SERVER_ERRORS.contains(&code) {
            Lookup::Unavailable(code.to_string())
        } else {
            Lookup::Refused(code.to_string())
        };
    }
    if record.deleted == Some(true) {
        return Lookup::NotIssued;
    }
    let Some(value) = record
        .fields
        .as_ref()
        .and_then(|fields| fields.signed_ticket.as_ref())
        .map(|ticket| ticket.value.as_str())
    else {
        return Lookup::Unavailable("an answer without a ticket".to_string());
    };
    match base64::engine::general_purpose::STANDARD.decode(value) {
        Ok(ticket) if !ticket.is_empty() => Lookup::Issued(ticket),
        _ => Lookup::Unavailable("an unreadable ticket".to_string()),
    }
}

/// CloudKit error codes are upper-case identifiers; anything else is shown
/// as unrecognized rather than echoed.
fn displayable_server_error(code: &str) -> &str {
    let identifier = !code.is_empty()
        && code.len() <= 40
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_');
    if identifier {
        code
    } else {
        "an unrecognized error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CDHASH: &str = "2333a682bac997f34eb811423fc9630552dc316a";
    const RECORD: &str = "2/2/2333a682bac997f34eb811423fc9630552dc316a";
    const TICKET: &[u8] = b"s8ch stapled notarization ticket";

    fn issued(ticket: &[u8]) -> serde_json::Value {
        serde_json::json!({ "records": [{
            "recordName": RECORD,
            "recordType": "DeveloperIDTicket",
            "fields": { "signedTicket": {
                "value": base64::engine::general_purpose::STANDARD.encode(ticket),
                "type": "BYTES",
            }},
            "pluginFields": {},
            "recordChangeTag": "mwpb0rxw",
            "deleted": false,
        }]})
    }

    fn record_error(code: &str) -> serde_json::Value {
        serde_json::json!({ "records": [{
            "recordName": RECORD,
            "reason": "Record not found",
            "serverErrorCode": code,
        }]})
    }

    /// Answers the ticket lookup with `answers` in turn, the last one for
    /// every later request.
    async fn ticket_service(answers: Vec<ResponseTemplate>) -> MockServer {
        let server = MockServer::start().await;
        let last = answers.len() - 1;
        for (index, answer) in answers.into_iter().enumerate() {
            let mock = Mock::given(method("POST"))
                .and(path("/lookup"))
                .and(header("content-type", "application/json"))
                .and(body_json(
                    serde_json::json!({ "records": [{ "recordName": RECORD }] }),
                ))
                .respond_with(answer);
            if index == last {
                mock.mount(&server).await;
            } else {
                mock.up_to_n_times(1).mount(&server).await;
            }
        }
        server
    }

    async fn confirm(server: &MockServer, retries: usize) -> (Result<(), LpmError>, Vec<Duration>) {
        let mut waits = Vec::new();
        let result = confirm_stapled_ticket(
            &lookup_client().unwrap(),
            &format!("{}/lookup", server.uri()),
            CDHASH,
            TICKET,
            &vec![Duration::from_millis(1); retries],
            |delay, _| waits.push(delay),
        )
        .await;
        (result, waits)
    }

    async fn lookups(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    #[tokio::test]
    async fn stapled_ticket_matching_apple_s_record_is_confirmed_with_one_lookup() {
        let server = ticket_service(vec![
            ResponseTemplate::new(200).set_body_json(issued(TICKET)),
        ])
        .await;

        let (result, waits) = confirm(&server, 5).await;

        result.unwrap();
        assert!(waits.is_empty());
        assert_eq!(lookups(&server).await, 1);
    }

    #[tokio::test]
    async fn ticket_check_outlasts_a_brief_outage_of_apple_s_ticket_service() {
        let server = ticket_service(vec![
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_json(record_error("THROTTLED")),
            ResponseTemplate::new(429),
            ResponseTemplate::new(408),
            ResponseTemplate::new(200).set_body_string("<html>captive portal</html>"),
            ResponseTemplate::new(200).set_body_bytes(vec![b' '; RESPONSE_MAX_BYTES + 1]),
            ResponseTemplate::new(200).set_body_json(issued(TICKET)),
        ])
        .await;

        let (result, waits) = confirm(&server, 6).await;

        result.unwrap();
        assert_eq!(waits.len(), 6);
        assert_eq!(lookups(&server).await, 7);
    }

    #[tokio::test]
    async fn lasting_outage_of_apple_s_ticket_service_fails_as_a_network_error() {
        let server = ticket_service(vec![ResponseTemplate::new(503)]).await;

        let (result, waits) = confirm(&server, 5).await;

        let error = result.unwrap_err();
        assert!(matches!(error, LpmError::Network(_)), "{error:?}");
        let error = error.to_string();
        assert!(error.contains("did not answer"), "{error}");
        assert!(error.contains("HTTP 503"), "{error}");
        assert_eq!(waits.len(), 5);
        assert_eq!(lookups(&server).await, 6);
    }

    #[tokio::test]
    async fn unreachable_ticket_service_is_retried_then_reported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut waits = Vec::new();

        let error = confirm_stapled_ticket(
            &lookup_client().unwrap(),
            &format!("http://{address}/lookup"),
            CDHASH,
            TICKET,
            &[Duration::from_millis(1); 2],
            |delay, _| waits.push(delay),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, LpmError::Network(_)), "{error:?}");
        assert_eq!(waits.len(), 2);
    }

    #[tokio::test]
    async fn stapled_ticket_other_than_apple_s_record_is_rejected_without_retrying() {
        let server = ticket_service(vec![
            ResponseTemplate::new(200).set_body_json(issued(b"another release's ticket")),
        ])
        .await;

        let (result, waits) = confirm(&server, 5).await;

        let error = result.unwrap_err().to_string();
        assert!(error.contains("not the one Apple issued"), "{error}");
        assert!(waits.is_empty());
        assert_eq!(lookups(&server).await, 1);
    }

    #[tokio::test]
    async fn code_apple_never_notarized_is_rejected_without_retrying() {
        let server = ticket_service(vec![
            ResponseTemplate::new(200).set_body_json(record_error("NOT_FOUND")),
        ])
        .await;

        let (result, waits) = confirm(&server, 5).await;

        let error = result.unwrap_err();
        assert!(matches!(error, LpmError::SelfUpdate(_)), "{error:?}");
        assert!(error.to_string().contains("has not issued"), "{error}");
        assert!(waits.is_empty());
        assert_eq!(lookups(&server).await, 1);
    }

    #[tokio::test]
    async fn deleted_ticket_record_is_rejected_without_retrying() {
        let mut deleted = issued(TICKET);
        deleted["records"][0]["deleted"] = serde_json::Value::Bool(true);
        let server = ticket_service(vec![ResponseTemplate::new(200).set_body_json(deleted)]).await;

        let (result, waits) = confirm(&server, 5).await;

        assert!(result.unwrap_err().to_string().contains("revoked"));
        assert!(waits.is_empty());
    }

    #[tokio::test]
    async fn refused_lookup_fails_at_once_and_names_the_refusal() {
        for (answer, refusal) in [
            (
                ResponseTemplate::new(200).set_body_json(record_error("ACCESS_DENIED")),
                "ACCESS_DENIED",
            ),
            (ResponseTemplate::new(400), "HTTP 400"),
            (
                ResponseTemplate::new(302).insert_header("location", "https://example.com/"),
                "HTTP 302",
            ),
        ] {
            let server = ticket_service(vec![answer]).await;

            let (result, waits) = confirm(&server, 5).await;

            let error = result.unwrap_err().to_string();
            assert!(error.contains(refusal), "{error}");
            assert!(waits.is_empty(), "{refusal} was retried");
            assert_eq!(lookups(&server).await, 1, "{refusal} was retried");
        }
    }

    #[test]
    fn answer_about_another_record_is_not_taken_for_this_one() {
        let mut other = issued(TICKET);
        other["records"][0]["recordName"] =
            serde_json::Value::from("2/2/0000000000000000000000000000000000000000");

        assert!(matches!(
            parse_lookup(&serde_json::to_vec(&other).unwrap(), RECORD),
            Lookup::Unavailable(_)
        ));
    }

    /// install.sh's harness feeds the same malformed records to its parser.
    #[test]
    fn malformed_record_fields_are_classified_as_install_sh_classifies_them() {
        let mut deleted_string = issued(TICKET);
        deleted_string["records"][0]["deleted"] = serde_json::Value::from("yes");
        let mut numeric_error = record_error("NOT_FOUND");
        numeric_error["records"][0]["serverErrorCode"] = serde_json::Value::from(5);
        let mut numeric_ticket = issued(TICKET);
        numeric_ticket["records"][0]["fields"]["signedTicket"]["value"] =
            serde_json::Value::from(5);

        let mut array_deleted = issued(TICKET);
        array_deleted["records"][0]["deleted"] = serde_json::json!([false]);
        let mut array_ticket = issued(TICKET);
        let value = array_ticket["records"][0]["fields"]["signedTicket"]["value"].clone();
        array_ticket["records"][0]["fields"]["signedTicket"]["value"] = serde_json::json!([value]);
        let record = issued(TICKET)["records"][0].clone();
        let null_record = serde_json::json!({ "records": [record, null] });
        let dict_records = serde_json::json!({ "records": { "0": record } });

        for answer in [
            deleted_string,
            numeric_error,
            numeric_ticket,
            array_deleted,
            array_ticket,
            null_record,
            dict_records,
        ] {
            assert_eq!(
                parse_lookup(&serde_json::to_vec(&answer).unwrap(), RECORD),
                Lookup::Unavailable("an unreadable answer".to_string()),
                "{answer}"
            );
        }
        assert_eq!(
            parse_lookup(&serde_json::to_vec(&record_error("")).unwrap(), RECORD),
            Lookup::Refused("an unrecognized error".to_string())
        );
    }

    #[test]
    fn answers_that_name_no_single_ticket_are_not_taken_as_one() {
        let mut two_records = issued(TICKET);
        let record = two_records["records"][0].clone();
        two_records["records"].as_array_mut().unwrap().push(record);
        let mut empty_ticket = issued(b"");
        empty_ticket["records"][0]["fields"]["signedTicket"]["value"] = serde_json::Value::from("");
        let mut undecodable_ticket = issued(TICKET);
        undecodable_ticket["records"][0]["fields"]["signedTicket"]["value"] =
            serde_json::Value::from("not base64!");

        for (answer, detail) in [
            (
                serde_json::json!({ "records": [] }),
                "an answer about another record",
            ),
            (two_records, "an answer about another record"),
            (empty_ticket, "an unreadable ticket"),
            (undecodable_ticket, "an unreadable ticket"),
        ] {
            assert_eq!(
                parse_lookup(&serde_json::to_vec(&answer).unwrap(), RECORD),
                Lookup::Unavailable(detail.to_string()),
                "{answer}"
            );
        }
    }

    #[test]
    fn null_fields_apple_may_add_do_not_hide_the_ticket() {
        let mut answer = issued(TICKET);
        answer["records"][0]["deleted"] = serde_json::Value::Null;
        answer["records"][0]["zoneID"] = serde_json::Value::Null;

        assert_eq!(
            parse_lookup(&serde_json::to_vec(&answer).unwrap(), RECORD),
            Lookup::Issued(TICKET.to_vec())
        );
    }

    #[test]
    fn overlong_server_error_is_not_echoed() {
        let answer = serde_json::to_vec(&record_error(&"A".repeat(41))).unwrap();

        assert_eq!(
            parse_lookup(&answer, RECORD),
            Lookup::Refused("an unrecognized error".to_string())
        );
    }

    #[test]
    fn unrecognized_server_error_is_not_echoed() {
        let answer = serde_json::to_vec(&record_error("\u{1b}[31mbad")).unwrap();

        assert_eq!(
            parse_lookup(&answer, RECORD),
            Lookup::Refused("an unrecognized error".to_string())
        );
    }

    #[test]
    fn ticket_lookup_accepts_only_a_sha_256_code_directory_hash() {
        assert_eq!(record_name(CDHASH).unwrap(), RECORD);
        for malformed in [
            "",
            "2333A682BAC997F34EB811423FC9630552DC316A",
            "2333a682bac997f34eb811423fc9630552dc316a00",
            "2333a682bac997f34eb811423fc9630552dc316\"",
        ] {
            assert!(record_name(malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn ticket_retries_wait_out_the_same_outage_as_install_sh() {
        let install_sh = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh"),
        )
        .unwrap();
        let schedule = install_sh
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("for ticket_retry_delay in ")?
                    .strip_suffix("; do")
            })
            .expect("install.sh retries the notarization ticket check");
        let install_sh_delays = schedule
            .split_whitespace()
            .filter(|delay| *delay != "\"\"")
            .map(|delay| Duration::from_secs(delay.parse().unwrap()))
            .collect::<Vec<_>>();

        assert_eq!(install_sh_delays, RETRY_DELAYS);
    }

    #[test]
    fn ticket_lookup_classifies_answers_by_the_same_limits_as_install_sh() {
        let install_sh = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh"),
        )
        .unwrap();
        let assignment = |name: &str| {
            install_sh
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("install.sh sets {name}"))
                .trim_matches('"')
                .to_string()
        };

        assert_eq!(
            assignment("NOTARIZATION_TICKET_TRANSIENT_ERRORS")
                .split_whitespace()
                .collect::<Vec<_>>(),
            TRANSIENT_SERVER_ERRORS
        );
        assert_eq!(
            assignment("NOTARIZATION_TICKET_RESPONSE_MAX_BYTES"),
            RESPONSE_MAX_BYTES.to_string()
        );
    }

    #[test]
    fn ticket_lookup_queries_the_same_record_store_as_install_sh() {
        let install_sh = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh"),
        )
        .unwrap();

        assert!(
            install_sh.contains(&format!(
                "NOTARIZATION_TICKET_LOOKUP_URL=\"{TICKET_LOOKUP_URL}\""
            )),
            "install.sh must look tickets up where self-update does"
        );
        assert!(install_sh.contains("ticket_record=\"2/2/"));
    }
}
