<?php

namespace Models\src\Services\Utils\Encryption;

use Models\src\Services\Utils\BaseService;
use Zephyrus\Core\Session;
use Zephyrus\Security\Cryptography;

class EncryptionService extends BaseService
{
    private const string CONTEXT_KEY = 'user_context';

    /**
     * Derives a symmetric key from password & salt via PBKDF2-SHA256.
     */
    public function deriveUserKey(string $password, string $salt): string
    {
        return Cryptography::deriveEncryptionKey($password, $salt);
    }

    /**
     * Encrypts and stores [user_id + userKey] in session.
     */
    public function storeUserContext(string $userId, string $userKey): void
    {
        $payload = json_encode([
            'user_id' => $userId,
            'key'     => $userKey,
        ]);

        Session::set(self::CONTEXT_KEY, Cryptography::encrypt($payload));
    }

    /**
     * Checks if we have both user ID and userKey in session.
     */
    public static function isAuthenticated(): bool
    {
        return self::getUserIdFromContext() !== null
            && self::getUserKeyFromContext() !== null;
    }

    /**
     * Clears the entire session.
     */
    public static function destroySession(): void
    {
        Session::destroy();
    }

    /**
     * Retrieves the user_id from the encrypted session payload.
     */
    public static function getUserIdFromContext(): ?string
    {
        $enc = Session::get(self::CONTEXT_KEY);
        if ($enc === null) {
            return null;
        }
        $data = json_decode(Cryptography::decrypt($enc), true);
        return $data['user_id'] ?? null;
    }

    /**
     * Retrieves the userKey (hex) from the encrypted session payload.
     */
    public static function getUserKeyFromContext(): ?string
    {
        $enc = Session::get(self::CONTEXT_KEY);
        if ($enc === null) {
            return null;
        }
        $data = json_decode(Cryptography::decrypt($enc), true);
        return $data['key'] ?? null;
    }

    /**
     * Envelope-encrypt with the userKey: random DEK for payload, wrapped under userKey-derived pubkey.
     */
    public function encryptWithUserKey(string $plaintext, string $userKey): string
    {
        return KeyUtils::encryptEnvelope($plaintext, $userKey);
    }

    /**
     * Envelope-decrypt: unwrap DEK then decrypt payload.
     */
    public function decryptWithUserKey(string $envelopeJson, string $userKey): ?string
    {
        return KeyUtils::decryptEnvelope($envelopeJson, $userKey);
    }

    /**
     * Hashes a plaintext password.
     */
    public function hashPassword(string $password): string
    {
        return Cryptography::hashPassword($password);
    }

    /**
     * Verifies a plaintext password against a stored hash.
     */
    public function verifyPassword(string $plainText, string $hashed): bool
    {
        return Cryptography::verifyHashedPassword($plainText, $hashed);
    }

    /**
     * Computes a SHA-256 hash of the given data (hex-encoded output).
     */
    public function hash256(string $data): string
    {
        return Cryptography::hash($data, 'sha256');
    }

    /**
     * Generates a cryptographically secure random hex-encoded salt.
     */
    public function generateSalt(int $length = 32): string
    {
        return Cryptography::randomHex($length);
    }

    /**
     * Re-wraps an existing envelope under a new userKey (fast key rotation).
     */
    public function rewrapEnvelope(string $envelopeJson, string $oldKey, string $newKey): string
    {
        return KeyUtils::rewrapEnvelope($envelopeJson, $oldKey, $newKey);
    }

    /**
     * Generates public key from a hex userKey.
     */
    public function generatePublicKey(string $userKey): string
    {
        return KeyUtils::generatePublicKeyFromUserKey($userKey);
    }

    /**
     * Seals (encrypts) plaintext to a recipient’s Base64 public key.
     */
    public function encryptWithPublicKey(string $plaintext, string $base64PublicKey): string
    {
        return KeyUtils::sealWithPublicKey($plaintext, $base64PublicKey);
    }

    /**
     * Opens data sealed with encryptWithPublicKey(), using this user’s keypair.
     */
    public function decryptFromPublicKey(string $sealedBase64, string $userKey): string
    {
        return KeyUtils::openSealedData($sealedBase64, $userKey);
    }

}

