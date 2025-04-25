<?php
require_once __DIR__ . '/paillier_encryption.php';

class HomomorphicKeyManagement {
    private $keyStorePath;
    private $paillier;
    
    public function __construct($keyStorePath = '../keys') {
        $this->keyStorePath = $keyStorePath;
        $this->paillier = new PaillierEncryption();
        
        // Ensure the key store directory exists and is writable
        if (!file_exists($this->keyStorePath)) {
            if (!mkdir($this->keyStorePath, 0777, true)) {
                throw new Exception("Failed to create key store directory: " . $this->keyStorePath);
            }
        }
        
        if (!is_writable($this->keyStorePath)) {
            throw new Exception("Key store directory is not writable: " . $this->keyStorePath);
        }
    }
    
    public function generateUserKeys($userId) {
        try {
            // Generate Paillier keys
            $p = gmp_nextprime(gmp_random_bits(512));
            $q = gmp_nextprime(gmp_random_bits(512));
            $n = gmp_mul($p, $q);
            $n2 = gmp_pow($n, 2);
            $lambda = gmp_lcm(gmp_sub($p, 1), gmp_sub($q, 1));
            $g = gmp_add($n, 1);
            $mu = $this->paillier->modInverse($lambda, $n);
            
            $paillierKeyPair = [
                'public' => [
                    'n' => gmp_strval($n),
                    'g' => gmp_strval($g)
                ],
                'private' => [
                    'lambda' => gmp_strval($lambda),
                    'mu' => gmp_strval($mu)
                ]
            ];
            
            // Store Paillier keys
            $this->storeKey($userId, 'paillier_private', $paillierKeyPair['private']);
            $this->storeKey($userId, 'paillier_public', $paillierKeyPair['public']);
            
            return $paillierKeyPair;
        } catch (Exception $e) {
            // Clean up any files that might have been created
            @unlink($this->getKeyPath($userId, 'paillier_private'));
            @unlink($this->getKeyPath($userId, 'paillier_public'));
            throw new Exception("Failed to generate and store Paillier keys: " . $e->getMessage());
        }
    }
    
    private function storeKey($userId, $type, $key) {
        $filename = $this->getKeyPath($userId, $type);
        if (is_array($key)) {
            $key = json_encode($key);
        }
        if (file_put_contents($filename, $key, LOCK_EX) === false) {
            throw new Exception("Failed to write $type key file");
        }
        chmod($filename, 0600);
    }
    
    private function getKeyPath($userId, $type) {
        return $this->keyStorePath . DIRECTORY_SEPARATOR . $type . '_' . $userId . '.pem';
    }
    
    public function getPaillierKeys($userId) {
        $publicKey = file_get_contents($this->getKeyPath($userId, 'paillier_public'));
        $privateKey = file_get_contents($this->getKeyPath($userId, 'paillier_private'));
        
        if ($publicKey === false || $privateKey === false) {
            throw new Exception("Failed to read Paillier keys for user: " . $userId);
        }
        
        return [
            'public' => json_decode($publicKey, true),
            'private' => json_decode($privateKey, true)
        ];
    }
}
?> 