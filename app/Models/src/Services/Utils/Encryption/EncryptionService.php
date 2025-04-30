<?php

namespace Models\src\Services\Utils\Encryption;

use Zephyrus\Security\Cryptography;

final class EncryptionService
{
    /**
     * Derives a symmetric key (in raw binary) from a password and salt using Argon2id.
     */
    public function deriveUserKey(string $password, string $salt): string
    {
        return CryptoUtils::deriveCryptoKey($password, $salt);
    }

    /**
     * Encrypts a plaintext using an envelope-encryption scheme.
     * A random symmetric DEK is generated and sealed with the user's keypair.
     */
    public function encryptWithUserKey(string $plaintext, string $userKey): string
    {
        return KeyUtils::encryptEnvelope($plaintext, $userKey);
    }

    /**
     * Decrypts envelope-encrypted data:
     * - Unwraps the DEK sealed to the user's keypair
     * - Uses the DEK to decrypt the payload
     */
    public function decryptWithUserKey(string $envelopeJson, string $userKey): string
    {
        return KeyUtils::decryptEnvelope($envelopeJson, $userKey);
    }

    /**
     * Hashes a plaintext password using Zephyrus' built-in hashing method (likely bcrypt).
     */
    public function hashPassword(string $password): string
    {
        return Cryptography::hashPassword($password);
    }

    /**
     * Verifies a plaintext password against its previously stored hash.
     */
    public function verifyPassword(string $plainText, string $hashed): bool
    {
        return Cryptography::verifyHashedPassword($plainText, $hashed);
    }

    /**
     * Computes a SHA-256 hash of arbitrary data, hex-encoded.
     */
    public function hash256(string $data): string
    {
        return Cryptography::hash($data, 'sha256');
    }

    /**
     * Generates a cryptographically secure random salt, hex-encoded.
     */
    public function generateSalt(int $length = 32): string
    {
        return Cryptography::randomHex($length);
    }

    /**
     * Rewraps an encrypted envelope under a new userKey (e.g. after password change).
     */
    public function rewrapEnvelope(string $envelopeJson, string $oldKey, string $newKey): string
    {
        return KeyUtils::rewrapEnvelope($envelopeJson, $oldKey, $newKey);
    }

    /**
     * Generates a Base64-encoded public key from a hex-encoded userKey.
     */
    public function generatePublicKey(string $userKey): string
    {
        return KeyUtils::generatePublicKeyFromUserKey($userKey);
    }

    /**
     * Seals (encrypts) plaintext to a recipient’s public key.
     * Only the holder of the private key can decrypt it.
     */
    public function encryptWithPublicKey(string $plaintext, string $base64PublicKey): string
    {
        return KeyUtils::sealWithPublicKey($plaintext, $base64PublicKey);
    }

    /**
     * Decrypts sealed data using the user's keypair.
     */
    public function decryptFromPublicKey(string $sealedBase64, string $userKey): string
    {
        return KeyUtils::openSealedData($sealedBase64, $userKey);
    }

}

