use anyhow::Result;
use ndarray::Array2;
use ort::{
    session::Session,
    value::TensorRef,
};
use serde_json;
use std::fs::File;

pub struct AiModel {
    pub feature_names: Vec<String>,
    pub session: Session,
}

impl AiModel {
    pub fn new() -> Result<Self> {
        let feature_names: Vec<String> =
            serde_json::from_reader(
                File::open("models/feature_columns.json")?
            )?;

        println!("Loaded {} features", feature_names.len());

        let session = Session::builder()?
            .commit_from_file("models/lightgbm.onnx")?;

        println!("Loaded ONNX model");

        
        Ok(Self {
            feature_names,
            session,
        })
    }

    pub fn predict(&mut self, features: Vec<f32>) -> Result<f32> {
        assert_eq!(features.len(), self.feature_names.len());

        let input = Array2::from_shape_vec((1, features.len()), features)?;

        let outputs = self.session.run(ort::inputs![
            TensorRef::from_array_view(input.view())?
        ])?;

        let (_, probs) = outputs[1].try_extract_tensor::<f32>()?;

        Ok(probs[1])
    }
}