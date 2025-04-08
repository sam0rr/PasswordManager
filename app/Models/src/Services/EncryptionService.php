<?php

namespace Models\src\Services;

use InvalidArgumentException;
use RuntimeException;
use SodiumException;
use Zephyrus\Core\Session;
use Zephyrus\Security\Cryptography;

class EncryptionService extends BaseService
{
    private const string CONTEXT_KEY = 'user_context';

    public function deriveUserKey(string $password, string $salt): string
    {
        return Cryptography::deriveEncryptionKey($password, $salt);
    }

    public function storeUserContext(string $userId, string $userKey): void
    {
        $payload = json_encode([
            'user_id' => $userId,
            'key' => $userKey
        ]);

        $encryptedPayload = Cryptography::encrypt($payload);
        Session::set(self::CONTEXT_KEY, $encryptedPayload);
    }

    public function getUserKeyFromContext(): ?string
    {
        $payload = Session::get(self::CONTEXT_KEY);
        if (is_null($payload)) {
            return null;
        }

        $data = json_decode(Cryptography::decrypt($payload), true);
        return $data['key'] ?? null;
    }

    public function getUserIdFromContext(): ?string
    {
        $payload = Session::get(self::CONTEXT_KEY);
        if (is_null($payload)) {
            return null;
        }

        $data = json_decode(Cryptography::decrypt($payload), true);
        return $data['user_id'] ?? null;
    }

    public function encryptWithUserKey(string $data, string $userKey): string
    {
        return Cryptography::encrypt($data, $userKey);
    }

    public function decryptWithUserKey(string $cipherText, string $userKey): ?string
    {
        return Cryptography::decrypt($cipherText, $userKey);
    }

    public function hashPassword(string $password): string
    {
        return Cryptography::hashPassword($password);
    }

    public function verifyPassword(string $plainText, string $hashed): bool
    {
        return Cryptography::verifyHashedPassword($plainText, $hashed);
    }

    public function hash256(string $data): string
    {
        return Cryptography::hash($data, 'sha256');
    }

    public function generateSalt(int $length = 32): string
    {
        return Cryptography::randomHex($length);
    }

    public function generatePublicKey(string $userKey): string
    {
        $binaryKey = hex2bin(mb_substr($userKey, 0, 64));

        if ($binaryKey === false || strlen($binaryKey) !== SODIUM_CRYPTO_SCALARMULT_BYTES) {
            throw new InvalidArgumentException("Invalid private key format for public key derivation.");
        }

        try {
            $publicKey = sodium_crypto_scalarmult_base($binaryKey);
        } catch (SodiumException $e) {
            throw new RuntimeException("Failed to generate public key: " . $e->getMessage(), 0, $e);
        }

        return base64_encode($publicKey);
    }

    public function encryptWithPublicKey(string $plainText, string $basePublicKey): string
    {
        $publicKey = base64_decode($basePublicKey);

        if ($publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException("Invalid public key format.");
        }

        try {
            $sealed = sodium_crypto_box_seal($plainText, $publicKey);
            return base64_encode($sealed);
        } catch (SodiumException $e) {
            throw new RuntimeException("Encryption with public key failed: " . $e->getMessage(), 0, $e);
        }
    }

    public function decryptFromPublicKey(string $cipherText, string $publicKey, string $userKey): ?string
    {
        $binaryPrivateKey = hex2bin(mb_substr($userKey, 0, 64));
        if ($binaryPrivateKey === false || strlen($binaryPrivateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidArgumentException("Invalid private key.");
        }

        $binaryPublicKey = base64_decode($publicKey);
        if ($binaryPublicKey === false || strlen($binaryPublicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException("Invalid public key.");
        }

        // Décoder le texte chiffré de base64
        $binaryCipherText = base64_decode($cipherText);
        if ($binaryCipherText === false) {
            throw new InvalidArgumentException("Invalid cipher text format.");
        }

        try {
            $keyPair = $this->buildKeyPair($binaryPrivateKey, $binaryPublicKey);
            $plaintext = sodium_crypto_box_seal_open($binaryCipherText, $keyPair);
            if ($plaintext === false) {
                throw new RuntimeException("Decryption failed: invalid message or mismatched keys.");
            }
            return $plaintext;
        } catch (SodiumException $e) {
            throw new RuntimeException("An error occurred during decryption: " . $e->getMessage(), 0, $e);
        }
    }

    private function buildKeyPair(string $privateKey, string $publicKey): string
    {
        try {
            return sodium_crypto_box_keypair_from_secretkey_and_publickey($privateKey, $publicKey);
        } catch (SodiumException $e) {
            throw new RuntimeException("An error occurred when making the key pair: " . $e->getMessage(), 0, $e);
        }
    }

    public static function destroySession(): void
    {
        Session::destroy();
    }

}
