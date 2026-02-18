fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic_build::compile_protos("proto/semantic_engine.proto")?;
    // Skip proto compilation since protoc is missing and we don't need the gRPC server for the library integration.
    Ok(())
}
