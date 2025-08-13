use vultisig::qr;

fn main() {
    let session_id = "test-session-123";
    let host = "192.168.1.100";
    let port = 8787;
    let network = "ETH";
    
    let uri = qr::generate_vultisig_uri(session_id, host, port, network);
    println!("Generated URI: {}", uri);
    
    match qr::display_qr_with_instructions(session_id, &uri, network) {
        Ok(_) => println!("QR code displayed successfully"),
        Err(e) => println!("Error displaying QR code: {}", e),
    }
}
