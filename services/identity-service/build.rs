fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/wslvault/identity/v1/service.proto",
                // Signing keys are wrapped by the crypto-service so they sit
                // under the root KEK, and therefore under the seal.
                "../../proto/wslvault/crypto/v1/service.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
