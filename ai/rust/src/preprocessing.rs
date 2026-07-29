use std::{
    collections::{HashMap, HashSet}
};
use anyhow::{anyhow, Result,Context};
use serde_json::{json, Map, Value};
use std::fs::File;
use crate::PredictionRequest;

pub fn build_features(
    request: PredictionRequest,
    expected: &[String]
) -> Result<Vec<f32>> {
    // ------------------------------
    // Transaction features
    // ------------------------------

    let mut row = find_transaction(&request.transaction)?
        .ok_or_else(|| anyhow!("Invalid transaction"))?;


        println!("{:?}", row.get("extension"));
        println!("{:?}", row.get("extension_length"));
    // ------------------------------
    // ModSecurity features
    // ------------------------------

    let modsec = find_modsec(&request.modsec)?;
    for (k, v) in modsec {
        row.insert(format!("mod_security_{}", k), v);
    }

    // ------------------------------
    // Lua WAF features
    // ------------------------------

    let waf = find_waf(&request.lua)?;
    for (k, v) in waf {
        row.insert(format!("lua_detection_{}", k), v);
    }

    // ------------------------------
    // Read feature order
    // ------------------------------

    // let feature_columns: Vec<String> =
    //     serde_json::from_reader(
    //         File::open("./models/feature_columns.json")?
    //     )?;

    let feature_columns = expected;
    // ------------------------------
    // One-hot encode
    // ------------------------------

    let categorical = ["request_method", "extension"];
    for column in categorical {
        let value = row
            .remove(column)
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();

        let prefix = format!("{column}_");

        for feature in feature_columns {
             if feature == "extension_length" {
        continue;
    }
            if let Some(category) = feature.strip_prefix(&prefix) {
                println!(
    "INSERT {} = {}",
    feature,
    value == category
);
                row.insert(
                    feature.clone(),
                    json!(value == category),
                );
            }
        }
    }

    // ------------------------------
    // Build feature vector
    // ------------------------------

    let ignore = [
        "request_id",
        "req_number",
        "label",
        "header_fingerprint",
    ];

    let mut features = Vec::with_capacity(feature_columns.len());
    let mut feature_names = Vec::with_capacity(feature_columns.len());

    

    for feature_name in feature_columns {

        if ignore.contains(&feature_name.as_str()) {
            continue;
        }
if feature_name == "extension_length" {
    println!("Before remove: {:?}", row.get("extension_length"));
}
        let value = row.remove(feature_name).unwrap_or(json!(0));

        let feature = match value {
            Value::Bool(b) => {
                if b { 1.0 } else { 0.0 }
            }

            Value::Number(n) => {
                n.as_f64().unwrap_or(0.0) as f32
            }

            Value::String(ref s) => {
                s.parse::<f32>().unwrap_or(0.0)
            }

            _ => 0.0,
        };

        feature_names.push(feature_name.clone());
        features.push(feature);
    }

//     if let Some(idx) = feature_columns
//     .iter()
//     .position(|f| f == "extension_length")
// {
//     features[idx] = 3.0;
// }
    if feature_names != expected {
        println!("Feature order mismatch!");

        for (i, (built, exp)) in feature_names.iter().zip(expected.iter()).enumerate() {
            if built != exp {
                println!("{:3}: built='{}' expected='{}'", i, built, exp);
            }
        }
    }

    println!("==============================");
    println!("Feature dump");
    println!("==============================");

    // for (name, value) in feature_columns.iter().zip(features.iter()) {
    //     println!("{:<40} {}", name, value);
    // }
    // compare_with_csv(
    // 113798,
    // &feature_names,
    // &features,
    // )?;
    Ok(features)
    }



fn compare_with_csv(
    req_number: i32,
    feature_names: &[String],
    features: &[f32],
) -> anyhow::Result<()> {
    let mut rdr = csv::Reader::from_path(
        "../../dataset_builder/final_dataset/test_dataset.csv"
    )?;

    let headers = rdr.headers()?.clone();

    let req_idx = headers
        .iter()
        .position(|h| h == "req_number")
        .unwrap();

    // Find the matching row
    for record in rdr.records() {
        let record = record?;

        if record[req_idx].parse::<i32>().unwrap() != req_number {
            continue;
        }

        println!("Comparing request {}\n", req_number);

        let header_map: HashMap<&str, usize> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| (h, i))
            .collect();

        let mut differences = 0;

        for (name, rust_value) in feature_names.iter().zip(features.iter()) {
            let Some(idx) = header_map.get(name.as_str()) else {
                println!("Missing column in CSV: {}", name);
                continue;
            };

            let csv_value = record[*idx]
                .parse::<f32>()
                .unwrap_or(0.0);

            if (rust_value - csv_value).abs() > 1e-6 {
                differences += 1;

                println!(
                    "{:<40} rust={:<12} csv={}",
                    name,
                    rust_value,
                    csv_value
                );
            }
        }

        println!("\nTotal differences: {}", differences);

        return Ok(());
    }

    println!("Request {} not found in CSV", req_number);

    Ok(())
}


    fn find_transaction(
        line: &str,
    ) -> Result<Option<HashMap<String, Value>>> {

            let value: Value = serde_json::from_str(line)?;

                let obj = value["features"]
                    .as_object()
                    .unwrap()
                    .clone();

                return Ok(Some(obj.into_iter().collect()));

        Ok(None)
}


fn find_modsec(
    line: &str,
) -> Result<HashMap<String, Value>> {



        let audit: Value = serde_json::from_str(line)?;

        let headers = &audit["transaction"]["request"]["headers"];

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
        
        let mut blocked = false;
        
        for message in &messages {


            if message["details"]["ruleId"].as_str() == Some("949110") {
                    blocked = true;
                }

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
            "decision".into(),
            serde_json::Value::from(if blocked { 1 } else { 0 }),
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
    

    // Ok(HashMap::new())
}




fn find_waf(
    line: &str,
) -> Result<HashMap<String, Value>> {
    


        let value: Value = serde_json::from_str(line)?;

        

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
    

    // Ok(HashMap::new())
}