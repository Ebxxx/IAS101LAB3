<?php

// Path to the certificate and private key
$certPath = __DIR__ . '/cert.pem';
$keyPath = __DIR__ . '/key.pem';

// Verify certificate and key exist
if (!file_exists($certPath) || !file_exists($keyPath)) {
    die("Certificate or key file not found. Please generate them first.\n");
}

// Create a SSL context
$context = stream_context_create([
    'ssl' => [
        'local_cert' => $certPath,
        'local_pk' => $keyPath,
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
        'ciphers' => 'HIGH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1',  // Allow only strong ciphers
        'disable_compression' => true,
        'honor_cipher_order' => true,
        'security_level' => 2,
    ]
]);

// Use a non-privileged port (e.g., 8443)
$port = 8443;       

// Create a socket and bind it to the specified port
$socket = @stream_socket_server("tcp://0.0.0.0:$port", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

if (!$socket) {
    die("Failed to create TLS server: $errstr ($errno)\n");
}

echo "TLS server is running on tls://0.0.0.0:$port\n";

// Handle incoming connections
while ($client = @stream_socket_accept($socket, -1)) {
    echo "New connection established\n";

    // Enable crypto on the client socket
    if (!stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER)) {
        echo "Failed to enable crypto: " . openssl_error_string() . "\n";
        fclose($client);
        continue;
    }

    // Read data from the client
    $data = fread($client, 1024);
    echo "Received: $data\n";

    // Send a response back to the client
    fwrite($client, "Hello from TLS server!\n");

    // Close the connection
    fclose($client);
}

fclose($socket);
?>