fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored protoc binary so that the build succeeds even when the
    // host machine does not have protoc installed.
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .expect("vendored protoc binary must be available");
    std::env::set_var("PROTOC", protoc_path);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["../../proto/wslvault/audit/v1/service.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
