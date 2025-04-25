<?php
require_once 'asymmetric/ntru_encryption.php';
require_once 'asymmetric/ecc_encryption.php';
require_once 'homomorphic/paillier_encryption.php';

class KeyManagement {
    private $keyStorePath;
    private $ntru;
    private $ecc;
    private $paillier;
    
    public function __construct($keyStorePath = '../keys', $cipherMode = 'AES-256-CBC') {
        $this->keyStorePath = $keyStorePath;
        $this->ntru = new NTRUEncryption();
        $this->ecc = new ECCEncryption($cipherMode);
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
    
    // Generate and store new key pair for a user
    public function generateUserKeys($userId) {
        try {
            // Generate NTRU, ECC, and Paillier key pairs
            $ntruKeyPair = $this->ntru->generateKeyPair();
            $eccKeyPair = $this->ecc->generateKeyPair();
            
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
            
            // Store all keys
            $this->storeKey($userId, 'ntru_private', $ntruKeyPair['privateKey']);
            $this->storeKey($userId, 'ntru_public', $ntruKeyPair['publicKey']);
            $this->storeKey($userId, 'ecc_private', $eccKeyPair['private']);
            $this->storeKey($userId, 'ecc_public', $eccKeyPair['public']);
            $this->storeKey($userId, 'paillier_private', $paillierKeyPair['private']);
            $this->storeKey($userId, 'paillier_public', $paillierKeyPair['public']);
            
            return [
                'ntru' => [
                    'public' => $ntruKeyPair['publicKey'],
                    'private' => $ntruKeyPair['privateKey']
                ],
                'ecc' => [
                    'public' => $eccKeyPair['public'],
                    'private' => $eccKeyPair['private']
                ],
                'paillier' => $paillierKeyPair
            ];
        } catch (Exception $e) {
            // Clean up any files that might have been created
            @unlink($this->getKeyPath($userId, 'ntru_private'));
            @unlink($this->getKeyPath($userId, 'ntru_public'));
            @unlink($this->getKeyPath($userId, 'ecc_private'));
            @unlink($this->getKeyPath($userId, 'ecc_public'));
            @unlink($this->getKeyPath($userId, 'paillier_private'));
            @unlink($this->getKeyPath($userId, 'paillier_public'));
            throw new Exception("Failed to generate and store keys: " . $e->getMessage());
        }
    }
    
    private function storeKey($userId, $type, $key) {
        $filename = $this->getKeyPath($userId, $type);
        // JSON encode array keys before storing
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
    
    public function getNTRUKeys($userId) {
        $publicKey = file_get_contents($this->getKeyPath($userId, 'ntru_public'));
        $privateKey = file_get_contents($this->getKeyPath($userId, 'ntru_private'));
        
        if ($publicKey === false || $privateKey === false) {
            throw new Exception("Failed to read NTRU keys for user: " . $userId);
        }
        
        return [
            'public' => json_decode($publicKey, true),
            'private' => json_decode($privateKey, true)
        ];
    }
    
    public function getECCKeys($userId) {
        $publicKey = file_get_contents($this->getKeyPath($userId, 'ecc_public'));
        $privateKey = file_get_contents($this->getKeyPath($userId, 'ecc_private'));
        
        if ($publicKey === false || $privateKey === false) {
            throw new Exception("Failed to read ECC keys for user: " . $userId);
        }
        
        return [
            'public' => $publicKey,
            'private' => $privateKey
        ];
    }
}
?> 
