<?php

namespace Models\src\Services\Utils\Encryption;

use InvalidArgumentException;
use RuntimeException;

final class CryptoUtils
{
    private function __construct() {}

    private const OPSLIMIT      = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    private const MEMLIMIT      = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    private const ALG           = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
    private const KEY_LENGTH    = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    private const NONCE_LENGTH  = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * Derives a strong binary key from a password and hex-salt using Argon2id.
     *
     * - Switched from PBKDF2-SHA256 → Argon2id (Cryptography of Zephyrus) for memory-hard GPU/ASIC resistance.
     * - Outputs a raw binary key of length KEY_LENGTH.
     */
    public static function deriveCryptoKey(
        string $password,
        string $salt,
        int $length = self::KEY_LENGTH
    ): string {
        $saltBin = hex2bin($salt);
        if ($saltBin === false || strlen($saltBin) < SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new InvalidArgumentException(
                "Salt must be hex of at least " . (SODIUM_CRYPTO_PWHASH_SALTBYTES * 2) . " chars"
            );
        }

        $key = sodium_crypto_pwhash(
            $length,
            $password,
            $saltBin,
            self::OPSLIMIT,
            self::MEMLIMIT,
            self::ALG
        );

        self::zeroMemory($saltBin);

        return $key;
    }

    /**
     * Encrypt raw bytes (nonce || ciphertext) with XChaCha20-Poly1305.
     */
    public static function encryptRaw(string $plaintext, string $key): string
    {
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new InvalidArgumentException("Invalid key length for encryption");
        }

        $nonce = random_bytes(self::NONCE_LENGTH);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            "",
            $nonce,
            $key
        );
        return $nonce . $cipher;
    }

    /**
     * Encrypt + Base64‐encode for safe storage/transit.
     */
    public static function encrypt(string $plaintext, string $key): string
    {
        return base64_encode(self::encryptRaw($plaintext, $key));
    }

    /**
     * Decrypt raw nonce||ciphertext bytes.
     */
    public static function decryptRaw(string $combined, string $key): string
    {
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new InvalidArgumentException("Invalid key length for decryption");
        }

        $nonceSize = self::NONCE_LENGTH;
        if (strlen($combined) < $nonceSize) {
            throw new RuntimeException("Invalid AEAD payload");
        }

        $nonce  = mb_substr($combined, 0, $nonceSize, '8bit');
        $cipher = mb_substr($combined, $nonceSize, null, '8bit');

        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $cipher,
            "",
            $nonce,
            $key
        );

        if ($plain === false) {
            throw new RuntimeException("AEAD decryption failed or data corrupted");
        }

        return $plain;
    }

    /**
     * Decrypt a Base64‐encoded blob.
     */
    public static function decrypt(string $encoded, string $key): string
    {
        $raw = base64_decode($encoded, true);
        if ($raw === false) {
            throw new RuntimeException("Invalid Base64 AEAD payload");
        }

        return self::decryptRaw($raw, $key);
    }

    /**
     * Securely clear sensitive data in memory.
     */
    public static function zeroMemory(string &$data): void
    {
        sodium_memzero($data);
    }

}

