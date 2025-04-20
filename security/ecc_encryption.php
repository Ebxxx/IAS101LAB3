<?php
require_once 'aes_gcm.php';
require_once 'chacha20.php';

class ECCEncryption {
    // Add new cipher options
    private $cipherMode = 'AES-256-CBC'; // Default for backward compatibility
    private $aesGcm;
    private $chaCha20;
    
    // Add constructor to allow cipher selection
    public function __construct($mode = 'AES-256-CBC') {
        $allowedModes = ['AES-256-CBC', 'AES-256-GCM', 'CHACHA20'];
        if (in_array($mode, $allowedModes)) {
            $this->cipherMode = $mode;
        }
        $this->aesGcm = new AES_GCM_Encryption();
        $this->chaCha20 = new ChaCha20_Encryption();
    }
    
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
    
    // Modify encrypt method to support different modes
    public function encrypt($data, $publicKey) {
        try {
            $symmetricKey = random_bytes(32);
            $iv = random_bytes($this->cipherMode === 'AES-256-CBC' ? 16 : 12); // GCM and ChaCha20 use 12 bytes
        } catch (Exception $e) {
            throw new Exception("Failed to generate random bytes: " . $e->getMessage());
        }
        
        // Encrypt the symmetric key with RSA public key
        if (!openssl_public_encrypt($symmetricKey, $encryptedKey, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new Exception("Failed to encrypt symmetric key: " . openssl_error_string());
        }
        
        // Encrypt data using selected cipher mode
        switch ($this->cipherMode) {
            case 'AES-256-GCM':
                $result = $this->aesGcm->encrypt($data, $symmetricKey, $iv);
                $package = [
                    'mode' => 'AES-256-GCM',
                    'encrypted_key' => base64_encode($encryptedKey),
                    'iv' => base64_encode($iv),
                    'tag' => $result['tag'],
                    'data' => $result['ciphertext']
                ];
                break;
                
            case 'CHACHA20':
                $encryptedData = $this->chaCha20->encrypt($data, $symmetricKey, $iv);
                $package = [
                    'mode' => 'CHACHA20',
                    'encrypted_key' => base64_encode($encryptedKey),
                    'nonce' => base64_encode($iv),
                    'data' => $encryptedData
                ];
                break;
                
            default: // AES-256-CBC
                $encryptedData = openssl_encrypt(
                    $data,
                    $this->cipherMode,
                    $symmetricKey,
                    OPENSSL_RAW_DATA,
                    $iv
                );
                $package = [
                    'mode' => 'AES-256-CBC',
                    'encrypted_key' => base64_encode($encryptedKey),
                    'iv' => base64_encode($iv),
                    'data' => base64_encode($encryptedData)
                ];
        }
        
        return base64_encode(json_encode($package));
    }
    
    // Modify decrypt method to support different modes
    public function decrypt($encryptedPackage, $privateKey) {
        $package = json_decode(base64_decode($encryptedPackage), true);
        if (!$package || !isset($package['mode'])) {
            throw new Exception("Invalid encrypted package format");
        }
        
        // Decrypt the symmetric key
        $encryptedKey = base64_decode($package['encrypted_key']);
        if (!openssl_private_decrypt($encryptedKey, $symmetricKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new Exception("Failed to decrypt symmetric key: " . openssl_error_string());
        }
        
        // Decrypt data based on mode
        switch ($package['mode']) {
            case 'AES-256-GCM':
                $iv = base64_decode($package['iv']);
                $decryptedData = $this->aesGcm->decrypt(
                    $package['data'],
                    $symmetricKey,
                    $iv,
                    $package['tag']
                );
                break;
                
            case 'CHACHA20':
                $nonce = base64_decode($package['nonce']);
                $decryptedData = $this->chaCha20->decrypt(
                    $package['data'],
                    $symmetricKey,
                    $nonce
                );
                break;
                
            default: // AES-256-CBC
                $iv = base64_decode($package['iv']);
                $encryptedData = base64_decode($package['data']);
                $decryptedData = openssl_decrypt(
                    $encryptedData,
                    'AES-256-CBC',
                    $symmetricKey,
                    OPENSSL_RAW_DATA,
                    $iv
                );
        }
        
        if ($decryptedData === false) {
            throw new Exception("Failed to decrypt data: " . openssl_error_string());
        }
        
        return $decryptedData;
    }
}
?> 