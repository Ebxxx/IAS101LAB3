<?php
require_once '../security/tls/tls_handshake.php';

try {
    // Initialize TLS handshake
    $tls = new TLSHandshake();
    $context = $tls->startHandshake();
    
    echo "Attempting to connect to TLS server...\n";
    
    // Connect to the TLS server
    $socket = $tls->secureConnection('localhost', 8443, $context);
    
    echo "Connected successfully!\n";
    
    // Send a test message
    $message = "Hello from TLS client!\n";
    fwrite($socket, $message);
    echo "Sent message: $message";
    
    // Read the server's response
    $response = fread($socket, 1024);
    echo "Received response: $response";
    
    // Close the connection
    fclose($socket);
    echo "Connection closed.\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?> 