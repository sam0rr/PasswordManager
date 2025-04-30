<?php

namespace Models\src\Services\Utils;

use InvalidArgumentException;
use RuntimeException;
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
     * Encrypts and stores [ user_id + userKey ] in session.
     */
    public function storeUserContext(string $userId, string $userKey): void
    {
        $payload = json_encode([
            'user_id' => $userId,
            'key'     => $userKey,
        ]);

        Session::set(self::CONTEXT_KEY, Cryptography::encrypt($payload));
    }

    public static function isAuthenticated(): bool
    {
        return !is_null(self::getUserIdFromContext())
            && !is_null(self::getUserKeyFromContext());
    }

    /** Destroys the entire session (e.g. on logout). */
    public static function destroySession(): void
    {
        Session::destroy();
    }

    public static function getUserIdFromContext(): ?string
    {
        $enc = Session::get(self::CONTEXT_KEY);
        if ($enc === null) {
            return null;
        }
        $data = json_decode(Cryptography::decrypt($enc), true);
        return $data['user_id'] ?? null;
    }

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
     * Symmetric encrypt/decrypt wrappers.
     */
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

    /**
     * Generates public key from userKey.
     */
    public function generatePublicKey(string $userKey): string
    {
        $keypair = $this->getKeypairFromUserKey($userKey);
        return base64_encode(sodium_crypto_box_publickey($keypair));
    }

    /**
     * Seals data to recipient's public key.
     */
    public function encryptWithPublicKey(string $plainText, string $base64PublicKey): string
    {
        $pub = $this->decodePublicKey($base64PublicKey);
        return base64_encode(sodium_crypto_box_seal($plainText, $pub));
    }

    /**
     * Opens sealed data using user's keypair.
     */
    public function decryptFromPublicKey(
        string $base64CipherText,
        string $base64PublicKey,
        string $userKey
    ): ?string {
        $keypair = $this->getKeypairFromUserKey($userKey);
        $secret  = sodium_crypto_box_secretkey($keypair);
        $pub     = $this->decodePublicKey($base64PublicKey);

        $sealed = base64_decode($base64CipherText, true);
        if ($sealed === false) {
            throw new RuntimeException("Invalid Base64 ciphertext.");
        }

        $pair  = sodium_crypto_box_keypair_from_secretkey_and_publickey($secret, $pub);
        $plain = sodium_crypto_box_seal_open($sealed, $pair);
        if ($plain === false) {
            throw new RuntimeException("Failed to decrypt sealed message.");
        }

        return $plain;
    }

    /**
     * Rebuilds a sodium keypair from hex userKey.
     */
    private function getKeypairFromUserKey(string $userKey): string
    {
        $raw = hex2bin($userKey);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidArgumentException(
                "User key must be hex of " . (SODIUM_CRYPTO_SECRETBOX_KEYBYTES * 2) . " chars."
            );
        }
        $seed = hash('sha256', $raw, true);
        return sodium_crypto_box_seed_keypair($seed);
    }

    /**
     * Decodes & validates Base64 public key.
     */
    private function decodePublicKey(string $base64): string
    {
        $decoded = base64_decode($base64, true);
        if ($decoded === false || strlen($decoded) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(
                "Public key must be Base64 of " . SODIUM_CRYPTO_BOX_PUBLICKEYBYTES . " bytes."
            );
        }
        return $decoded;
    }
}
