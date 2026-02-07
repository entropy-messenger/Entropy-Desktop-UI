use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::sync::{Arc, Mutex};
use hound::{WavWriter, WavSpec};
use tauri::{AppHandle, Emitter, Manager};

pub struct AudioRecorder {
    pub stream: Option<cpal::Stream>,
    pub recording_path: Option<std::path::PathBuf>,
}

impl AudioRecorder {
    pub fn new() -> Self {
        Self {
            stream: None,
            recording_path: None,
        }
    }

    pub fn start_recording(&mut self, app: AppHandle) -> Result<String, String> {
        let host = cpal::default_host();
        let device = host.default_input_device().ok_or("No input device available")?;
        let config = device.default_input_config().map_err(|e| e.to_string())?;
        let spec = WavSpec {
            channels: config.channels() as u16,
            sample_rate: config.sample_rate(),
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };

        let temp_dir = app.path().app_data_dir().map_err(|e: tauri::Error| e.to_string())?;
        if !temp_dir.exists() {
            std::fs::create_dir_all(&temp_dir).map_err(|e| e.to_string())?;
        }
        let path = temp_dir.join("temp_recording.wav");
        self.recording_path = Some(path.clone());

        let writer = WavWriter::create(&path, spec).map_err(|e| e.to_string())?;
        let writer = Arc::new(Mutex::new(Some(writer)));
        let writer_clone = writer.clone();
        let app_clone = app.clone();

        let err_fn = |err| eprintln!("an error occurred on stream: {}", err);

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => device.build_input_stream(
                &config.into(),
                move |data: &[f32], _: &_| {
                    let mut sum = 0.0;
                    if let Ok(mut guard) = writer_clone.lock() {
                        if let Some(w) = guard.as_mut() {
                            for &sample in data {
                                let _ = w.write_sample((sample * i16::MAX as f32) as i16);
                                sum += sample.abs();
                            }
                        }
                    }
                    let avg = sum / (data.len() as f32).max(1.0);
                    let _ = app_clone.emit("recording-volume", avg);
                },
                err_fn,
                None,
            ),
            cpal::SampleFormat::I16 => device.build_input_stream(
                &config.into(),
                move |data: &[i16], _: &_| {
                    let mut sum = 0.0;
                    if let Ok(mut guard) = writer_clone.lock() {
                        if let Some(w) = guard.as_mut() {
                            for &sample in data {
                                let _ = w.write_sample(sample);
                                sum += (sample as f32 / i16::MAX as f32).abs();
                            }
                        }
                    }
                    let avg = sum / (data.len() as f32).max(1.0);
                    let _ = app_clone.emit("recording-volume", avg);
                },
                err_fn,
                None,
            ),
            _ => return Err("Unsupported sample format".to_string()),
        }.map_err(|e| e.to_string())?;

        stream.play().map_err(|e| e.to_string())?;
        self.stream = Some(stream);

        Ok("Recording started".to_string())
    }

    pub fn stop_recording(&mut self) -> Result<Vec<u8>, String> {
        if let Some(stream) = self.stream.take() {
            drop(stream); // This should stop the recording and drop the writer handle in the closure
        }

        if let Some(path) = self.recording_path.take() {
            let data = std::fs::read(&path).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(path);
            Ok(data)
        } else {
            Err("No recording in progress".to_string())
        }
    }
}
