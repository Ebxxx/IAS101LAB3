<?php

class TLSHandshake {
    private $certPath;
    private $keyPath;

    public function __construct($certPath = null, $keyPath = null) {
        $this->certPath = $certPath ?? __DIR__ . '/cert.pem';
        $this->keyPath = $keyPath ?? __DIR__ . '/key.pem';
        
        if (!file_exists($this->certPath) || !file_exists($this->keyPath)) {
            throw new Exception("Certificate or key file not found");
        }
    }

    public function startHandshake() {
        // Create a new SSL context
        $context = stream_context_create([
            'ssl' => [
                'local_cert' => $this->certPath,
                'local_pk' => $this->keyPath,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'ciphers' => 'HIGH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1',
                'disable_compression' => true,
                'honor_cipher_order' => true,
                'security_level' => 2,
            ]
        ]);

        return $context;
    }

    public function secureConnection($host, $port, $context) {
        try {
            // Open a secure connection
            $socket = @stream_socket_client("tls://$host:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

            if (!$socket) {
                throw new Exception("Failed to connect: $errstr ($errno)");
            }

            // Check if crypto is already enabled
            $crypto = stream_get_meta_data($socket);
            if (!isset($crypto['crypto'])) {
                // Only enable crypto if it's not already enabled
                if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT)) {
                    fclose($socket);
                    throw new Exception("Failed to enable crypto: " . openssl_error_string());
                }
            }

            return $socket;
        } catch (Exception $e) {
            if (isset($socket) && is_resource($socket)) {
                fclose($socket);
            }
            throw $e;
        }
    }
}
?> 