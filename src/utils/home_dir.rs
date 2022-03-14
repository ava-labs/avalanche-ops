use dirs::home_dir;

pub fn named(name: &str, ext: Option<&str>) -> String {
    let home = home_dir().unwrap();
    let file_path = home.join(format!("{}{}", name, ext.unwrap_or("")));
    let file_path = file_path.as_os_str().to_str().unwrap();
    String::from(file_path)
}
