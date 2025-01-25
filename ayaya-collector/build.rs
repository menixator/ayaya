fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/ayaya_collection.proto")?;
    Ok(())
}
