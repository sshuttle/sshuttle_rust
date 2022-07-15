mod options;

fn main() {
    let args = options::parse();
    println!("Hello, world! {args:?}");
}
