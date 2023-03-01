use std::time::Duration;

pub fn duration_string(duration: &Duration) -> String {
    let seconds = duration.as_secs() % 60;
    let minutes = (duration.as_secs() / 60) % 60;
    let hours = (duration.as_secs() / 60) / 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}
