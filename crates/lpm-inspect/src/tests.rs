//! Integration tests for the inspector server.

#[cfg(test)]
mod integration_tests {
    use crate::state::InspectorState;
    use lpm_tunnel::webhook::CapturedWebhook;
    use std::collections::HashMap;

    fn url_with_token(port: u16, path: &str, token: &str) -> String {
        let sep = if path.contains('?') { '&' } else { '?' };
        format!("http://127.0.0.1:{port}{path}{sep}token={token}")
    }

    fn make_webhook(id: &str, status: u16) -> CapturedWebhook {
        CapturedWebhook {
            id: id.to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("stripe-signature".to_string(), "t=123,v1=abc".to_string()),
            ]),
            request_body: br#"{"type":"charge.succeeded","id":"evt_123"}"#.to_vec(),
            response_status: status,
            response_headers: HashMap::new(),
            response_body: br#"{"received":true}"#.to_vec(),
            duration_ms: 42,
            provider: Some(lpm_tunnel::webhook::WebhookProvider::Stripe),
            summary: "Stripe: charge.succeeded".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
        }
    }

    // ── State tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn state_push_and_retrieve() {
        let state = InspectorState::new(3000);
        state.push(make_webhook("w1", 200)).await;
        state.push(make_webhook("w2", 500)).await;

        assert_eq!(state.count().await, 2);

        let all = state.get_all().await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "w1");
        assert_eq!(all[1].id, "w2");
    }

    #[tokio::test]
    async fn state_get_by_id() {
        let state = InspectorState::new(3000);
        state.push(make_webhook("w1", 200)).await;
        state.push(make_webhook("w2", 404)).await;

        let found = state.get_by_id("w2").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().response_status, 404);

        let not_found = state.get_by_id("nonexistent").await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn state_tunnel_url() {
        let state = InspectorState::new(3000);
        assert!(state.get_tunnel_url().await.is_none());

        state
            .set_tunnel_url("https://acme.lpm.fyi".to_string())
            .await;
        assert_eq!(
            state.get_tunnel_url().await,
            Some("https://acme.lpm.fyi".to_string())
        );
    }

    #[tokio::test]
    async fn state_sse_broadcast() {
        let state = InspectorState::new(3000);
        let mut rx = state.subscribe();

        state.push(make_webhook("w1", 200)).await;

        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, "w1");
    }

    #[tokio::test]
    async fn state_local_port() {
        let state = InspectorState::new(8080);
        assert_eq!(state.local_port(), 8080);
    }

    #[tokio::test]
    async fn pending_state_does_not_claim_a_local_endpoint_before_discovery() {
        let state = InspectorState::pending();

        assert_eq!(state.local_port(), 0);
        let pending_status = crate::api::status(axum::extract::State(state.clone()))
            .await
            .unwrap()
            .0;
        assert!(!pending_status.local_ready);
        assert!(pending_status.local_url.is_none());

        state.set_local_target(lpm_common::LocalTarget::loopback(
            lpm_common::LocalScheme::Http,
            5173,
        ));
        assert_eq!(state.local_port(), 5173);
    }

    #[tokio::test]
    async fn state_preserves_the_complete_local_replay_target() {
        let target = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Https, 8443)
            .with_base_path("/hooks/");
        let state = InspectorState::new_for_target(target.clone());

        assert_eq!(state.local_target(), target);
        assert_eq!(state.local_port(), 8443);
    }

    // ── API response conversion tests ───────────────────────────

    #[test]
    fn request_summary_from_webhook() {
        let webhook = make_webhook("w1", 500);
        let summary = crate::api::RequestSummary::from(webhook);

        assert_eq!(summary.id, "w1");
        assert_eq!(summary.method, "POST");
        assert_eq!(summary.path, "/api/webhook");
        assert_eq!(summary.status, 500);
        assert!(summary.is_error);
        assert_eq!(summary.provider, Some("Stripe".to_string()));
        assert_eq!(summary.summary, "Stripe: charge.succeeded");
        assert!(!summary.has_signature_issue);
    }

    #[test]
    fn request_detail_from_webhook() {
        let webhook = make_webhook("w1", 200);
        let detail = crate::api::RequestDetail::from(webhook);

        assert_eq!(detail.id, "w1");
        match &detail.request_body {
            crate::api::BodyPayload::Text { data } => {
                assert!(data.contains("charge.succeeded"));
            }
            _ => panic!("expected text body"),
        }
        match &detail.response_body {
            crate::api::BodyPayload::Text { data } => {
                assert!(data.contains("received"));
            }
            _ => panic!("expected text body"),
        }
        assert_eq!(detail.request_body_size, 42); // length of the JSON body
        assert_eq!(detail.response_body_size, 17); // {"received":true}
    }

    #[test]
    fn request_detail_binary_body_is_typed() {
        let mut webhook = make_webhook("w1", 200);
        webhook.request_body = vec![0xFF, 0x00, 0xAB]; // non-UTF-8
        let detail = crate::api::RequestDetail::from(webhook);

        match &detail.request_body {
            crate::api::BodyPayload::Binary { data } => {
                assert!(!data.is_empty());
            }
            _ => panic!("expected binary body"),
        }
    }

    #[test]
    fn request_detail_empty_body() {
        let mut webhook = make_webhook("w1", 200);
        webhook.response_body = Vec::new();
        let detail = crate::api::RequestDetail::from(webhook);

        assert!(matches!(
            detail.response_body,
            crate::api::BodyPayload::Empty
        ));
    }

    #[test]
    fn body_payload_serialization() {
        let text = crate::api::BodyPayload::Text {
            data: "hello".to_string(),
        };
        let json = serde_json::to_value(&text).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["data"], "hello");

        let binary = crate::api::BodyPayload::Binary {
            data: "AQID".to_string(),
        };
        let json = serde_json::to_value(&binary).unwrap();
        assert_eq!(json["type"], "binary");

        let empty = crate::api::BodyPayload::Empty;
        let json = serde_json::to_value(&empty).unwrap();
        assert_eq!(json["type"], "empty");
    }

    // ── Server binding tests ────────────────────────────────────

    #[tokio::test]
    async fn server_starts_and_responds() {
        let state = InspectorState::new(3000);
        let handle = crate::start(state.clone(), 0).await;

        // Port 0 means the OS picks a free port — but our implementation
        // uses a fixed port. For testing, use a high random port.
        // Skip if port 0 is not supported by our implementation.
        if handle.is_err() {
            return;
        }

        let handle = handle.unwrap();
        assert!(!handle.url.is_empty());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn server_binds_to_specific_port() {
        let state = InspectorState::new(3000);
        // Use a high port unlikely to conflict
        let port = 14_400;
        let handle = crate::start(state, port).await;

        match handle {
            Ok(h) => {
                assert_eq!(h.port, port);
                assert!(h.url.contains(&port.to_string()));
                h.shutdown().await.unwrap();
            }
            Err(_) => {
                // Port may be in use — that's OK for CI
            }
        }
    }

    // ── HTTP endpoint tests ─────────────────────────────────────

    #[tokio::test]
    async fn api_status_endpoint() {
        let state = InspectorState::new(3000);
        let port = 14_401;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return, // Port in use — skip
        };

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(url_with_token(port, "/api/status", state.auth_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["inspector"], true);
        assert_eq!(body["local_port"], 3000);
        assert_eq!(body["local_url"], "http://127.0.0.1:3000/");
        assert_eq!(body["local_ready"], true);
        assert_eq!(body["captured_count"], 0);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_requests_endpoint() {
        let state = InspectorState::new(3000);
        let port = 14_402;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Push some webhooks
        state.push(make_webhook("w1", 200)).await;
        state.push(make_webhook("w2", 500)).await;

        let resp = reqwest::get(url_with_token(port, "/api/requests", state.auth_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["total"], 2);

        let items = body["items"].as_array().unwrap();
        // Newest first
        assert_eq!(items[0]["id"], "w2");
        assert_eq!(items[1]["id"], "w1");

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_requests_reopens_persisted_project_history() {
        let project = tempfile::tempdir().unwrap();
        let writer_db = crate::db::InspectorDb::open(project.path()).unwrap();
        let writer = InspectorState::with_db(3000, writer_db);
        writer.push(make_webhook("persisted-w1", 202)).await;
        writer.flush().await.unwrap();

        let reader_db = crate::db::InspectorDb::open(project.path()).unwrap();
        let reader = InspectorState::with_db(0, reader_db);
        let handle = crate::start(reader.clone(), 0).await.unwrap();

        let resp = reqwest::get(url_with_token(
            handle.port,
            "/api/requests",
            reader.auth_token(),
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], "persisted-w1");

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn persistent_state_records_named_sessions_without_a_browser_subscriber() {
        let db = crate::db::InspectorDb::open_temp().unwrap();
        let state = InspectorState::with_db(3000, db.clone());
        state
            .start_session(
                "session-no-ui".to_string(),
                Some("hooks.lpm.fyi".to_string()),
                3000,
                Some("stripe retries".to_string()),
            )
            .await
            .unwrap();
        state.push(make_webhook("session-request", 202)).await;
        state.end_session().await.unwrap();
        state.flush().await.unwrap();

        let sessions = db.list_sessions(10).await.unwrap();
        let requests = db
            .list_session_requests("session-no-ui", 10, 0)
            .await
            .unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name.as_deref(), Some("stripe retries"));
        assert!(sessions[0].ended_at.is_some());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id, "session-request");
    }

    #[tokio::test]
    async fn project_observer_revision_changes_after_an_external_capture() {
        let project = tempfile::tempdir().unwrap();
        let writer =
            InspectorState::with_db(3000, crate::db::InspectorDb::open(project.path()).unwrap());
        let observer = InspectorState::with_db_observer(
            0,
            crate::db::InspectorDb::open(project.path()).unwrap(),
        );
        let before = observer.database_revision().await.unwrap();

        writer.push(make_webhook("external-write", 201)).await;
        writer.flush().await.unwrap();

        assert!(observer.observes_database());
        assert_ne!(observer.database_revision().await.unwrap(), before);
    }

    #[tokio::test]
    async fn project_observer_revision_changes_when_an_external_session_starts_and_ends() {
        let project = tempfile::tempdir().unwrap();
        let writer =
            InspectorState::with_db(3000, crate::db::InspectorDb::open(project.path()).unwrap());
        let observer = InspectorState::with_db_observer(
            0,
            crate::db::InspectorDb::open(project.path()).unwrap(),
        );
        let before_start = observer.database_revision().await.unwrap();

        writer
            .start_session(
                "external-session".to_string(),
                Some("external.lpm.fyi".to_string()),
                3000,
                None,
            )
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let after_start = observer.database_revision().await.unwrap();

        writer.end_session().await.unwrap();
        writer.flush().await.unwrap();
        let after_end = observer.database_revision().await.unwrap();

        assert_ne!(after_start, before_start);
        assert_ne!(after_end, after_start);
    }

    #[tokio::test]
    async fn api_request_detail_endpoint() {
        let state = InspectorState::new(3000);
        let port = 14_403;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        state.push(make_webhook("w1", 200)).await;

        let resp = reqwest::get(url_with_token(port, "/api/requests/w1", state.auth_token()))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["id"], "w1");
        assert_eq!(body["request_body"]["type"], "text");
        assert!(
            body["request_body"]["data"]
                .as_str()
                .unwrap()
                .contains("charge.succeeded")
        );

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_request_detail_not_found() {
        let state = InspectorState::new(3000);
        let port = 14_404;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(url_with_token(
            port,
            "/api/requests/nonexistent",
            state.auth_token(),
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), 404);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_diff_endpoint() {
        let state = InspectorState::new(3000);
        let port = 14_406;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Push two webhooks with different bodies
        let mut w1 = make_webhook("diff-a", 200);
        w1.request_body = br#"{"type":"charge.succeeded","amount":1000}"#.to_vec();

        let mut w2 = make_webhook("diff-b", 500);
        w2.request_body = br#"{"type":"charge.succeeded","amount":2000,"currency":"usd"}"#.to_vec();

        state.push(w1).await;
        state.push(w2).await;

        let resp = reqwest::get(url_with_token(
            port,
            "/api/diff/diff-a/diff-b",
            state.auth_token(),
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["old_id"], "diff-a");
        assert_eq!(body["new_id"], "diff-b");

        // request_body should have diffs (amount changed, currency added)
        let req_diffs = body["request_body"].as_array().unwrap();
        assert!(req_diffs.len() >= 2);

        let summary = &body["request_body_summary"];
        assert!(summary["total"].as_u64().unwrap() >= 2);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_diff_not_found() {
        let state = InspectorState::new(3000);
        let port = 14_407;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(url_with_token(
            port,
            "/api/diff/nope1/nope2",
            state.auth_token(),
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), 404);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_rejects_unauthenticated_request() {
        let state = InspectorState::new(3000);
        let port = 14_408;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/api/status"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_rejects_wrong_token() {
        let state = InspectorState::new(3000);
        let port = 14_409;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!(
            "http://127.0.0.1:{port}/api/status?token=wrongtoken"
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), 401);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_rejects_cookie_auth() {
        // Cookies on `127.0.0.1` are host-scoped, not port-scoped, so a
        // cookie carrier would leak to every other localhost service.
        let state = InspectorState::new(3000);
        let port = 14_411;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/api/status"))
            .header(
                "Cookie",
                format!("lpm_inspector_token={}", state.auth_token()),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_html_response_does_not_set_inspector_cookie() {
        let state = InspectorState::new(3000);
        let port = 14_412;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!(
            "http://127.0.0.1:{port}/?token={}",
            state.auth_token()
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        for (name, value) in resp.headers().iter() {
            if name.as_str().eq_ignore_ascii_case("set-cookie") {
                let v = value.to_str().unwrap_or("");
                assert!(
                    !v.contains("lpm_inspector_token"),
                    "inspector must not set an auth-token cookie; got: {v}"
                );
            }
        }
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("sessionStorage.setItem(\"lpm_inspector_token\""),
            "expected SPA bootstrap to set sessionStorage; body sample: {}",
            &body[..body.len().min(400)]
        );
        assert!(
            body.contains("Authorization"),
            "expected SPA bootstrap to patch fetch with Authorization header"
        );
        assert!(
            body.contains("EventSource"),
            "expected SPA bootstrap to patch EventSource"
        );

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn api_accepts_bearer_header() {
        let state = InspectorState::new(3000);
        let port = 14_410;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/api/status"))
            .bearer_auth(state.auth_token())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_placeholder_served() {
        let state = InspectorState::new(3000);
        let port = 14_405;
        let handle = match crate::start(state.clone(), port).await {
            Ok(h) => h,
            Err(_) => return,
        };

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let body = resp.text().await.unwrap();
        assert!(body.contains("LPM Inspector"));
        assert!(body.contains("/api/status"));

        handle.shutdown().await.unwrap();
    }
}
