// mod ai;
// mod preprocessing;

// use anyhow::Result;

// fn main() -> Result<()> {
//     let mut model = ai::AiModel::new()?;

//     println!("Features: {}", model.feature_names.len());

//     println!("Inputs:");
//     for input in model.session.inputs() {
//         println!("{:#?}", input);
//     }

//     println!("Outputs:");
//     for output in model.session.outputs() {
//         println!("{:#?}", output);
//     }
//     let features = vec![0.0; model.feature_names.len()];

//     let score = model.predict(features)?;

//     println!("Score = {}", score);

//     preprocessing::preprocess_request()?;
//     Ok(())
// }

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct PredictionRequest {
    transaction: String,
    modsec: String,
    lua: String,
}

#[derive(Debug, Serialize)]
struct PredictionResponse {
    score: f32,
    decision: bool,
}



use crate::ai::AiModel;
use csv::Reader;
use std::fs::File;
use std::io::Write;

fn test_dataset(model: &mut AiModel) -> Result<()> {
    let mut rdr =
        Reader::from_path("../../dataset_builder/final_dataset/test_dataset.csv")?;

    let headers = rdr.headers()?.clone();

    // CSV header -> column index
    let header_map: HashMap<String, usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| (h.to_string(), i))
        .collect();

    // Load the feature order used during training
    let feature_columns: Vec<String> =
        serde_json::from_reader(File::open(
            "./models/feature_columns.json"
        )?)?;
    println!(
        "CSV headers: {}, model features: {}",
        headers.len(),
        feature_columns.len()
    );
    let label_index = header_map["label"];

    let rows: Vec<_> = rdr.records().collect::<Result<_, _>>()?;

    let mut correct = 0;
    let req_number_index = header_map["req_number"];
    for row in &rows {
    // for row in &rows {    
        let req_number = row
        .get(req_number_index)
        .unwrap()
        .parse::<u32>()
        .unwrap();

        let mut features = Vec::with_capacity(feature_columns.len());

        for feature in &feature_columns {
            let value = if let Some(&idx) = header_map.get(feature) {
                row.get(idx)
                    .unwrap_or("0")
                    .parse::<f32>()
                    .unwrap_or(0.0)
            } else {
                // Feature doesn't exist in this CSV
                0.0
            };

            features.push(value);
        }
        if req_number == 113798 {
    let mut f = File::create("csv_features.txt")?;

    for v in &features {
        writeln!(f, "{:.9}", v)?;
    }
}
        let score = model.predict(features)?;
        let pred = score > 0.5;

        let truth = row.get(label_index).unwrap() == "1";

        if pred == truth {
            correct += 1;
        }
        if(req_number == 113798 ){
println!(
            "score={:.6} pred={} truth={}",
            score,
            pred,
            truth
        );

        }
        
    }

    println!(
        "Accuracy: {:.2}%",
        correct as f32 * 100.0 / (rows.len()) as f32
    );
    // println!("CSV feature count: {}", feature_indices.len());
    // println!("Model feature count: {}", model.feature_names.len());
    // for &i in feature_indices.iter().take(20) {
    //     println!("{}", headers.get(i).unwrap());
    // }
    Ok(())
}

mod ai;
mod preprocessing;

use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};



const LISTEN_ADDR: &str = "127.0.0.1:9000";

fn handle_client(stream: TcpStream, model: &mut ai::AiModel) -> Result<()>{
    let mut reader = BufReader::new(stream);

    // Read one JSON request (newline-delimited)
    let mut line = String::new();
    reader.read_line(&mut line)?;

    println!("Received:");
    println!("{}", line);

    let request: PredictionRequest = serde_json::from_str(&line)?;
    let features = preprocessing::build_features(request,&model.feature_names)?;
    // println!("Model expects {}", model.feature_names.len());
    // println!("Built {}", features.len());

    // if features.len() != model.feature_names.len() {
    //     for (i, name) in model.feature_names.iter().enumerate() {
    //         println!("{:3}: {}", i, name);
    //     }
    // }
    // for (i, name) in model.feature_names.iter().enumerate() {
    //     println!("{:3}: {}", i, name);
    // }

    // println!("Model expects {}", model.feature_names.len());
    // let mut f = File::create("live_features.txt")?;

    // for v in &features {
    //     writeln!(f, "{:.9}", v)?;
    // }
    let score = model.predict(features)?;


    // let score = model.predict(vec![0.0; model.feature_names.len()])?;

    let response = PredictionResponse {
        score,
        decision: score > 0.5,
    };
    println!("{}", serde_json::to_string_pretty(&response)?);

    let stream = reader.get_mut();
   match writeln!(
    stream,
    "{}",
        serde_json::to_string(&response)?
    ) {
        Ok(_) => println!("response sent"),
        Err(e) => println!("write failed: {:?}", e),
    }

    Ok(())
}

fn main() -> Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDR)?;

    println!("Loading AI model...");
    let mut model = ai::AiModel::new()?;

    println!("Model loaded.");
    println!("Features: {}", model.feature_names.len());

    test_dataset(&mut model)?;

    println!("Listening on {}", LISTEN_ADDR);

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(e) = handle_client(stream, &mut model) {
                    eprintln!("Request failed: {e:#}");
                }
            }
            Err(e) => {
                eprintln!("Connection error: {e}");
            }
        }
    }

    Ok(())
}