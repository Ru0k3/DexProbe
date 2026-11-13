pub fn ok(msg: &str) {
    println!("[OK]    {msg}");
}

pub fn info(msg: &str) {
    println!("[INFO]  {msg}");
}

pub fn warn(msg: &str) {
    eprintln!("[WARN]  {msg}");
}

pub fn err(msg: &str) {
    eprintln!("[ERROR] {msg}");
}

pub fn step(msg: &str) {
    println!("[>>]    {msg}");
}

pub fn section(title: &str, width: usize) {
    let rule = "═".repeat(width);
    println!("\n{rule}\n  {title}\n{rule}");
}
