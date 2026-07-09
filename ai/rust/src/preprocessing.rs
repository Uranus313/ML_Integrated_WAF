use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
};
use anyhow::{anyhow, Result,Context};
use serde_json::{json, Map, Value};

const REQUEST_ID: &str = "2cbd1589929fe8617b45a44d64aba202";

pub fn preprocess_request() -> Result<()>{
    let mut row = find_transaction(REQUEST_ID)?
    .ok_or_else(|| anyhow!("Transaction not found"))?;

    let modsec = find_modsec(REQUEST_ID)?;
    for (k, v) in modsec {
        row.insert(format!("mod_security_{}", k), v);
    }

    let waf = find_waf(REQUEST_ID)?;
    for (k, v) in waf {
        row.insert(format!("lua_detection_{}", k), v);
    }

    // ------------------------------
    // Read CSV header
    // ------------------------------

    let mut rdr = csv::Reader::from_path("../../dataset_builder/final_dataset/dataset.csv").context("Failed to open ../logs/dataset.csv")?;
    let headers = rdr.headers()?.clone();

    // ------------------------------
    // One-hot encode
    // ------------------------------

    let categorical = ["request_method", "extension"];

    for column in categorical {
        let value = row
            .remove(column)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let prefix = format!("{}_", column);

        for h in headers.iter() {
            if h.starts_with(&prefix) {
                let category = &h[prefix.len()..];
                row.insert(h.to_string(), json!(value == category));
            }
        }
    }

    // ------------------------------
    // Build final feature vector
    // ------------------------------

    let ignore = ["request_id", "req_number", "label"];

    let mut feature_row = Map::new();

    for h in headers.iter() {
        if ignore.contains(&h) {
            continue;
        }

        feature_row.insert(
            h.to_string(),
            row.remove(h).unwrap_or(json!(0)),
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&feature_row)?
    );

    Ok(())
}

fn find_transaction(
    request_id: &str,
) -> Result<Option<HashMap<String, Value>>> {
    let file = BufReader::new(File::open("../../logs/transactions.jsonl").context("Failed to open ../logs/transactions.jsonl")?);

    for line in file.lines() {
        let value: Value = serde_json::from_str(&line?)?;

        if value["request_id"] == request_id {
            let obj = value["features"]
                .as_object()
                .unwrap()
                .clone();

            return Ok(Some(obj.into_iter().collect()));
        }
    }

    Ok(None)
}


fn find_modsec(
    request_id: &str,
) -> Result<HashMap<String, Value>> {
    let file = BufReader::new(File::open("../../logs/modsec_audit.log").context("Failed to open ../logs/modsec_audit.log")?,);

    for line in file.lines() {
        let line = line?;

        if line.trim().is_empty() {
            continue;
        }

        let audit: Value = serde_json::from_str(&line)?;

        let headers = &audit["transaction"]["request"]["headers"];

        if headers["X-WAF-Request-ID"].as_str() != Some(request_id) {
            continue;
        }

        let transaction = &audit["transaction"];

        let messages = transaction["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let mut anomaly_score = 0;

        let mut rule_ids = HashSet::new();

        let mut scanner_rule_count = 0;
        let mut xss_rule_count = 0;
        let mut sqli_rule_count = 0;
        let mut lfi_rule_count = 0;
        let mut rce_rule_count = 0;
        let mut php_rule_count = 0;

        let mut severity_0 = 0;
        let mut severity_1 = 0;
        let mut severity_2 = 0;
        let mut severity_3 = 0;
        let mut severity_4 = 0;

        for message in &messages {
            // --------------------------
            // Anomaly score
            // --------------------------

            if anomaly_score == 0 {
                if let Some(text) = message["message"].as_str() {
                    if text.contains("Inbound Anomaly Score") {
                        if let Some(score) = text.split("Total Score: ").nth(1) {
                            let score = score.trim_end_matches(')');
                            anomaly_score = score.parse::<i32>().unwrap_or(0);
                        }
                    }
                }
            }

            // --------------------------
            // Rule IDs
            // --------------------------

            if let Some(rule_id) = message["details"]["ruleId"].as_str() {
                rule_ids.insert(rule_id.to_string());
            }

            // --------------------------
            // Severity
            // --------------------------

            match message["details"]["severity"].as_str() {
                Some("0") => severity_0 += 1,
                Some("1") => severity_1 += 1,
                Some("2") => severity_2 += 1,
                Some("3") => severity_3 += 1,
                Some("4") => severity_4 += 1,
                _ => {}
            }

            // --------------------------
            // Tags
            // --------------------------

            if let Some(tags) = message["details"]["tags"].as_array() {
                for tag in tags {
                    if let Some(tag) = tag.as_str() {
                        if tag.contains("attack-reputation-scanner") {
                            scanner_rule_count += 1;
                        }
                        if tag.contains("attack-xss") {
                            xss_rule_count += 1;
                        }
                        if tag.contains("attack-sqli") {
                            sqli_rule_count += 1;
                        }
                        if tag.contains("attack-lfi") {
                            lfi_rule_count += 1;
                        }
                        if tag.contains("attack-rce") {
                            rce_rule_count += 1;
                        }
                        if tag.contains("attack-injection-php") {
                            php_rule_count += 1;
                        }
                    }
                }
            }
        }

        let mut out = HashMap::new();

        out.insert(
            "http_code".into(),
            transaction["response"]["http_code"].clone(),
        );

        out.insert("rule_count".into(), json!(messages.len()));
        out.insert("unique_rule_count".into(), json!(rule_ids.len()));
        out.insert("anomaly_score".into(), json!(anomaly_score));

        out.insert("scanner_rule_count".into(), json!(scanner_rule_count));

        out.insert("xss_rule_count".into(), json!(xss_rule_count));
        out.insert("sqli_rule_count".into(), json!(sqli_rule_count));
        out.insert("lfi_rule_count".into(), json!(lfi_rule_count));
        out.insert("rce_rule_count".into(), json!(rce_rule_count));
        out.insert("php_rule_count".into(), json!(php_rule_count));

        out.insert("severity_0".into(), json!(severity_0));
        out.insert("severity_1".into(), json!(severity_1));
        out.insert("severity_2".into(), json!(severity_2));
        out.insert("severity_3".into(), json!(severity_3));
        out.insert("severity_4".into(), json!(severity_4));

        return Ok(out);
    }

    Ok(HashMap::new())
}




fn find_waf(
    request_id: &str,
) -> Result<HashMap<String, Value>> {
    let file = BufReader::new(File::open("../../logs/waf.jsonl").context("Failed to open ../logs/waf.jsonl")?);

    for line in file.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let value: Value = serde_json::from_str(&line)?;

        if value["data"]["request_id"].as_str() != Some(request_id) {
            continue;
        }

        let reasons = value["data"]["reasons"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let mut xss_count = 0;
        let mut sqli_count = 0;
        let mut lfi_count = 0;
        let mut rce_count = 0;
        let mut cmd_count = 0;
        let mut upload_count = 0;

        for reason in &reasons {
            if let Some(reason) = reason.as_str() {
                if reason.starts_with("xss:") {
                    xss_count += 1;
                }
                if reason.starts_with("sqli:") {
                    sqli_count += 1;
                }
                if reason.starts_with("lfi:") {
                    lfi_count += 1;
                }
                if reason.starts_with("rce:") {
                    rce_count += 1;
                }
                if reason.starts_with("cmd:") {
                    cmd_count += 1;
                }
                if reason.starts_with("upload:") {
                    upload_count += 1;
                }
            }
        }

        let mut out = HashMap::new();

        out.insert(
            "decision".into(),
            json!(value["message"].as_str() == Some("Request blocked")),
        );

        out.insert(
            "score".into(),
            value["data"]["score"].clone(),
        );

        out.insert(
            "reason_count".into(),
            json!(reasons.len()),
        );

        out.insert("xss_count".into(), json!(xss_count));
        out.insert("sqli_count".into(), json!(sqli_count));
        out.insert("lfi_count".into(), json!(lfi_count));
        out.insert("rce_count".into(), json!(rce_count));
        out.insert("cmd_count".into(), json!(cmd_count));
        out.insert("upload_count".into(), json!(upload_count));

        return Ok(out);
    }

    Ok(HashMap::new())
}