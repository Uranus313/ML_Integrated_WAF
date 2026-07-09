mod ai;
mod preprocessing;

use anyhow::Result;

fn main() -> Result<()> {
    let mut model = ai::AiModel::new()?;

    println!("Features: {}", model.feature_names.len());

    println!("Inputs:");
    for input in model.session.inputs() {
        println!("{:#?}", input);
    }

    println!("Outputs:");
    for output in model.session.outputs() {
        println!("{:#?}", output);
    }
    let features = vec![0.0; model.feature_names.len()];

    let score = model.predict(features)?;

    println!("Score = {}", score);

    preprocessing::preprocess_request()?;
    Ok(())
}