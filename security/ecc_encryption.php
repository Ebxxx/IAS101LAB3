<?php


class ECCEncryption {
    private $cipher = 'AES-256-CBC';
    
    // Generate key pair (using RSA instead of ECC for Windows compatibility)
    public function generateKeyPair() {
        // Set OpenSSL configuration
        $opensslConfigPath = 'C:/xampp/php/extras/openssl/openssl.cnf';
        if (file_exists($opensslConfigPath)) {
            putenv("OPENSSL_CONF=$opensslConfigPath");
        }

        // Generate private key
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'config' => $opensslConfigPath
        ]);

        if ($privateKey === false) {
            throw new Exception("Failed to generate private key: " . openssl_error_string());
        }

        // Export private key to PEM format
        if (!openssl_pkey_export($privateKey, $privateKeyPem, null, ['config' => $opensslConfigPath])) {
            throw new Exception("Failed to export private key: " . openssl_error_string());
        }

        // Get public key
        $publicKeyDetails = openssl_pkey_get_details($privateKey);
        if ($publicKeyDetails === false) {
            throw new Exception("Failed to get public key: " . openssl_error_string());
        }

        return [
            'private' => $privateKeyPem,
            'public' => $publicKeyDetails['key']
        ];
    }
    
    // Encrypt data using hybrid encryption (RSA + AES)
    public function encrypt($data, $publicKey) {
        // Generate a random AES key
        try {
            $aesKey = random_bytes(32);
            $iv = random_bytes(16);
        } catch (Exception $e) {
            throw new Exception("Failed to generate random bytes: " . $e->getMessage());
        }
        
        // Encrypt the AES key with RSA public key
        if (!openssl_public_encrypt($aesKey, $encryptedKey, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new Exception("Failed to encrypt AES key: " . openssl_error_string());
        }
        
        // Encrypt the data with AES
        $encryptedData = openssl_encrypt(
            $data,
            $this->cipher,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($encryptedData === false) {
            throw new Exception("Failed to encrypt data: " . openssl_error_string());
        }
        
        // Combine all encrypted components
        $package = [
            'encrypted_key' => base64_encode($encryptedKey),
            'iv' => base64_encode($iv),
            'data' => base64_encode($encryptedData)
        ];
        
        return base64_encode(json_encode($package));
    }
    
    // Decrypt data using hybrid decryption
    public function decrypt($encryptedPackage, $privateKey) {
        // Decode the package
        $package = json_decode(base64_decode($encryptedPackage), true);
        if (!$package) {
            throw new Exception("Invalid encrypted package format");
        }
        
        // Extract components
        $encryptedKey = base64_decode($package['encrypted_key']);
        $iv = base64_decode($package['iv']);
        $encryptedData = base64_decode($package['data']);
        
        // Decrypt the AES key using RSA private key
        if (!openssl_private_decrypt($encryptedKey, $aesKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new Exception("Failed to decrypt AES key: " . openssl_error_string());
        }
        
        // Decrypt the data using AES
        $decryptedData = openssl_decrypt(
            $encryptedData,
            $this->cipher,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($decryptedData === false) {
            throw new Exception("Failed to decrypt data: " . openssl_error_string());
        }
        
        return $decryptedData;
    }
}
?> 