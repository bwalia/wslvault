fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/wslvault/secret/v1/service.proto",
                "../../proto/wslvault/crypto/v1/service.proto",
                "../../proto/wslvault/policy/v1/service.proto",
                "../../proto/wslvault/audit/v1/service.proto",
                "../../proto/wslvault/lease/v1/service.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
