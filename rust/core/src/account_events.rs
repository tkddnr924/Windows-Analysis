//! Structured account evidence, preserving the existing viewer's role rules.
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evidence {
    /// Role label used by the existing matcher.
    pub role: &'static str,
    /// True for SID evidence.
    pub is_sid: bool,
    /// Full payload path, or the system principal's UserID.
    pub field: String,
    /// Original scalar representation.
    pub value: String,
}

// Preserve the viewer's scalar and array representation.
fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => Some(
            values
                .iter()
                .filter_map(value_text)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        // Objects inside arrays retain their JSON representation.
        Value::Object(_) => Some(value.to_string()),
    }
}

fn extract_fields(
    value: &Value,
    prefix: &str,
    provider: &str,
    event_id: &str,
    evidence: &mut Vec<Evidence>,
) {
    let Value::Object(values) = value else { return };
    for (field, nested) in values {
        if nested.is_object() {
            let path = if prefix.is_empty() { field.clone() } else { format!("{prefix}.{field}") };
            extract_fields(nested, &path, provider, event_id, evidence);
            continue;
        }
        let key = field.to_ascii_lowercase();
        let role = account_sid_role(&key).map(|role| (role, true))
            .or_else(|| account_name_role(provider, event_id, &key).map(|role| (role, false)));
        let Some((role, is_sid)) = role else { continue };
        let Some(value) = value_text(nested) else { continue };
        let field = if prefix.is_empty() { field.clone() } else { format!("{prefix}.{field}") };
        if !evidence.iter().any(|item| item.role == role && item.is_sid == is_sid
            && item.field == field && item.value == value) {
            evidence.push(Evidence { role, is_sid, field, value });
        }
    }
}

fn account_sid_role(field: &str) -> Option<&'static str> {
    match field {
        "subjectsid" | "subjectusersid" | "subjectaccountsid" => Some("수행 계정"),
        "targetsid" | "targetusersid" | "targetaccountsid" => Some("대상 계정"),
        "membersid" | "membernamesid" => Some("그룹 구성원"),
        "accountsid" | "accountusersid" | "usersid" | "userusersid" | "callersid"
        | "callerusersid" | "clientsid" | "clientusersid" => Some("계정"),
        _ => None,
    }
}

fn account_name_role(provider: &str, event_id: &str, field: &str) -> Option<&'static str> {
    match field {
        "subjectname" | "subjectusername" | "subjectaccountname" => Some("수행 계정"),
        "targetname" | "targetusername" | "targetaccountname" => Some("대상 계정"),
        "membername" => Some("그룹 구성원"),
        "accountname" | "accountusername" | "username" | "userusername" | "callername"
        | "callerusername" | "clientname" | "clientusername" => Some("계정"),
        "param1"
            if provider == "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
                && event_id == "1149" =>
        {
            Some("RDP 세션 사용자")
        }
        "user"
            if provider == "Microsoft-Windows-TerminalServices-LocalSessionManager"
                && matches!(event_id, "21" | "22" | "23" | "24" | "25" | "39" | "40") =>
        {
            Some("RDP 세션 사용자")
        }
        _ => None,
    }
}

fn bare_name(value: &str) -> &str {
    value.trim().rsplit(['\\', '/']).next().unwrap_or_default()
        .split('@').next().unwrap_or_default().trim()
}


// Lowercase comparison matches the viewer without allocating normalized copies.
fn same_identity(left: &str, right: &str) -> bool {
    left.chars().flat_map(char::to_lowercase).eq(right.chars().flat_map(char::to_lowercase))
}

/// Parse the payload once; a malformed payload does not erase UserID.
pub(crate) fn extract(
    provider: &str,
    event_id: &str,
    user_id: &str,
    event_data: &str,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    if !user_id.is_empty() {
        evidence.push(Evidence {
            role: "이벤트 보안 주체", is_sid: true,
            field: "UserID".into(), value: user_id.into(),
        });
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(event_data) {
        extract_fields(&parsed, "", provider, event_id, &mut evidence);
    }
    evidence
}

/// Any SID field in a role blocks its name fallback, including empty or dash values.
pub(crate) fn matching<'a>(
    evidence: &'a [Evidence],
    wanted_sid: &str,
    wanted_name: &str,
) -> Vec<&'a Evidence> {
    let wanted_sid = wanted_sid.trim();
    let wanted_name = bare_name(wanted_name);
    let mut matched: Vec<_> = evidence.iter().filter(|item| {
        if item.is_sid {
            !wanted_sid.is_empty() && same_identity(item.value.trim(), wanted_sid)
        } else {
            !wanted_name.is_empty()
                && !evidence.iter().any(|other| other.role == item.role && other.is_sid)
                && same_identity(bare_name(&item.value), wanted_name)
        }
    }).collect();
    matched.sort_by_key(|item| item.role);
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const BOB_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";

    fn matched_tuples<'a>(evidence: &'a [Evidence], sid: &str, name: &str) -> Vec<(&'a str, bool, String, String)> {
        matching(evidence, sid, name)
            .into_iter()
            .map(|item| {
                (
                    item.role,
                    item.is_sid,
                    item.field.clone(),
                    item.value.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn wrong_sid_blocks_same_name_but_other_role_still_matches() {
        let data = format!(
            r#"{{"TargetUserSid":"{BOB_SID}","TargetUserName":"alice","SubjectUserName":"CONTOSO\\alice"}}"#
        );
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4624", "", &data);
        assert_eq!(evidence.len(), 3);

        let matched = matched_tuples(&evidence, ALICE_SID, "alice");
        assert_eq!(
            matched,
            vec![(
                "수행 계정",
                false,
                "SubjectUserName".to_string(),
                "CONTOSO\\alice".to_string()
            )]
        );
    }

    #[test]
    fn dash_sid_blocks_name_fallback() {
        let data = r#"{"TargetUserSid":"-","TargetUserName":"alice"}"#;
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4625", "", data);
        assert!(matching(&evidence, ALICE_SID, "alice").is_empty());
        assert!(matching(&evidence, "", "alice").is_empty());

        // An empty SID field still blocks name fallback.
        let empty = extract(
            "Microsoft-Windows-Security-Auditing",
            "4625",
            "",
            r#"{"TargetUserSid":"","TargetUserName":"alice"}"#,
        );
        assert_eq!(empty.len(), 2);
        assert!(matching(&empty, "", "alice").is_empty());
    }

    #[test]
    fn name_matching_normalises_domain_and_upn() {
        for raw in [
            "alice",
            "CONTOSO\\Alice",
            "contoso/alice",
            " ALICE ",
            "alice@contoso.com",
            "CONTOSO\\alice@contoso.com",
        ] {
            let data = format!(r#"{{"TargetUserName":{}}}"#, serde_json::json!(raw));
            let evidence = extract("Microsoft-Windows-Security-Auditing", "4720", "", &data);
            let matched = matching(&evidence, "", "alice");
            assert_eq!(matched.len(), 1, "{raw} 는 alice 로 정규화되어야 한다");
            assert_eq!(matched[0].value, raw, "원본 값은 그대로 보존한다");
        }
        let data = r#"{"TargetUserName":"alice.admin"}"#;
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4720", "", data);
        assert!(matching(&evidence, "", "alice").is_empty());
    }

    #[test]
    fn nested_paths_are_preserved_and_sid_match_is_case_insensitive() {
        let data = format!(
            r#"{{"Data":{{"Inner":{{"SubjectUserSid":"{}"}}}},"MemberSid":"{BOB_SID}"}}"#,
            ALICE_SID.to_lowercase()
        );
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4728", "", &data);
        let matched = matched_tuples(&evidence, &format!("  {ALICE_SID}  "), "");
        assert_eq!(
            matched,
            vec![(
                "수행 계정",
                true,
                "Data.Inner.SubjectUserSid".to_string(),
                ALICE_SID.to_lowercase()
            )]
        );
    }

    #[test]
    fn sid_match_wins_over_name_within_role() {
        let data = format!(r#"{{"TargetUserSid":"{ALICE_SID}","TargetUserName":"alice"}}"#);
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4624", "", &data);
        let matched = matched_tuples(&evidence, ALICE_SID, "alice");
        assert_eq!(
            matched,
            vec![(
                "대상 계정",
                true,
                "TargetUserSid".to_string(),
                ALICE_SID.to_string()
            )]
        );
    }

    #[test]
    fn rdp_name_fields_require_provider_and_event_id() {
        let param1 = r#"{"Param1":"CONTOSO\\alice"}"#;
        let user = r#"{"User":"CONTOSO\\alice"}"#;

        let hit = extract(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            "1149",
            "",
            param1,
        );
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].role, "RDP 세션 사용자");
        assert!(!hit[0].is_sid);
        assert_eq!(matching(&hit, "", "alice").len(), 1);

        assert!(extract(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            "1150",
            "",
            param1
        )
        .is_empty());
        assert!(extract("Microsoft-Windows-Security-Auditing", "1149", "", param1).is_empty());

        for event_id in ["21", "22", "23", "24", "25", "39", "40"] {
            let hit = extract(
                "Microsoft-Windows-TerminalServices-LocalSessionManager",
                event_id,
                "",
                user,
            );
            assert_eq!(hit.len(), 1, "LocalSessionManager {event_id}");
            assert_eq!(hit[0].role, "RDP 세션 사용자");
        }
        assert!(extract(
            "Microsoft-Windows-TerminalServices-LocalSessionManager",
            "41",
            "",
            user
        )
        .is_empty());
        assert!(extract(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            "21",
            "",
            user
        )
        .is_empty());
    }

    #[test]
    fn arbitrary_payload_and_arrays_are_not_identity() {
        let data = format!(
            r#"{{"RuleId":"{ALICE_SID}","Description":"user alice logged on",
                 "Data":["{ALICE_SID}","alice"],
                 "Nested":{{"FreeText":"CONTOSO\\alice"}}}}"#
        );
        let evidence = extract("Microsoft-Windows-Windows Firewall With Advanced Security", "2004", "", &data);
        assert!(evidence.is_empty(), "{evidence:?}");
        assert!(matching(&evidence, ALICE_SID, "alice").is_empty());
    }

    #[test]
    fn arrays_preserve_legacy_scalar_matching() {
        let data = format!(
            r#"{{"TargetUserName":["alice","bob"],"SubjectUserSid":["{ALICE_SID}","{BOB_SID}"]}}"#
        );
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4624", "", &data);
        assert_eq!(evidence.len(), 2);
        assert!(matching(&evidence, ALICE_SID, "alice").is_empty());

        // A single element joins to the same scalar value.
        let single = extract(
            "Microsoft-Windows-Security-Auditing",
            "4624",
            "",
            &format!(r#"{{"SubjectUserSid":["{ALICE_SID}"]}}"#),
        );
        assert_eq!(matching(&single, ALICE_SID, "").len(), 1);
    }

    #[test]
    fn user_id_survives_malformed_payload() {
        let evidence = extract(
            "Microsoft-Windows-Kernel-General",
            "12",
            ALICE_SID,
            "<not json>",
        );
        assert_eq!(
            matched_tuples(&evidence, ALICE_SID, ""),
            vec![(
                "이벤트 보안 주체",
                true,
                "UserID".to_string(),
                ALICE_SID.to_string()
            )]
        );
        // UserID is independent of payload roles.
        let data = format!(r#"{{"TargetUserSid":"{BOB_SID}","TargetUserName":"alice"}}"#);
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4624", ALICE_SID, &data);
        assert_eq!(matching(&evidence, ALICE_SID, "alice").len(), 1);
    }

    #[test]
    fn empty_inputs_produce_nothing() {
        assert!(extract("Provider", "1", "", "").is_empty());
        assert!(extract("Provider", "1", "", "{}").is_empty());
        let data = format!(r#"{{"TargetUserSid":"{ALICE_SID}"}}"#);
        let evidence = extract("Microsoft-Windows-Security-Auditing", "4624", "", &data);
        assert!(matching(&evidence, "   ", "  ").is_empty());
    }

}
