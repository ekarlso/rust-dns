// Utility function to turn "google.com" into a Vector of String
pub fn name_from_slice(s: &str) -> Vec<String> {
    s.split('.').map(|a: &str| a.to_string() ).collect::<Vec<String>>()
}