<?php

namespace Models\src\Services\Utils\Encryption;

use InvalidArgumentException;
use RuntimeException;

final class KeyUtils
{
    private function __construct() {}

    /**
     * Cache of keypairs derived from userKey (seeded X25519 keypairs).
     */
    private static array $keypairCache = [];

    /**
     * Generates or returns a cached keypair from a userKey (hex).
     */
    private static function getKeypairFromUserKey(string $userKey): string
    {
        if (!ctype_xdigit($userKey) || strlen($userKey) !== SODIUM_CRYPTO_BOX_SEEDBYTES * 2) {
            throw new InvalidArgumentException("User key must be hex of " . (SODIUM_CRYPTO_BOX_SEEDBYTES * 2) . " chars.");
        }

        $cacheKey = hash('sha256', $userKey);

        if (!isset(self::$keypairCache[$cacheKey])) {
            $raw = hex2bin($userKey);
            if ($raw === false) {
                throw new InvalidArgumentException("Invalid hex in user key.");
            }

            self::$keypairCache[$cacheKey] = sodium_crypto_box_seed_keypair($raw);
            CryptoUtils::zeroMemory($raw);
        }

        return self::$keypairCache[$cacheKey];
    }

    /**
     * Parses and validates a standard envelope JSON payload (must contain "d" and "k").
     */
    private static function parseEnvelope(string $json): array
    {
        $env = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE || !isset($env['d'], $env['k'])) {
            throw new InvalidArgumentException("Invalid envelope JSON");
        }
        return $env;
    }

    /**
     * Derives a Base64-encoded public key from a userKey.
     */
    public static function generatePublicKeyFromUserKey(string $userKey): string
    {
        $kp = self::getKeypairFromUserKey($userKey);
        return base64_encode(sodium_crypto_box_publickey($kp));
    }

    /**
     * Envelope-encrypts the plaintext using a random DEK sealed under userKey.
     */
    public static function encryptEnvelope(string $plaintext, string $userKey): string
    {
        $dek    = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $cipher = CryptoUtils::encrypt($plaintext, $dek);

        $kp        = self::getKeypairFromUserKey($userKey);
        $pubkey    = sodium_crypto_box_publickey($kp);
        $sealedDEK = sodium_crypto_box_seal($dek, $pubkey);
        CryptoUtils::zeroMemory($dek);

        $result = json_encode([
            'd' => $cipher,
            'k' => base64_encode($sealedDEK)
        ]);

        if ($result === false) {
            throw new RuntimeException("Failed to encode envelope");
        }

        return $result;
    }

    /**
     * Decrypts an envelope payload using the private key from userKey.
     */
    public static function decryptEnvelope(string $envelopeJson, string $userKey): string
    {
        $env = self::parseEnvelope($envelopeJson);

        $sealedDek = base64_decode($env['k'], true);
        if ($sealedDek === false) {
            throw new RuntimeException("Malformed DEK base64");
        }

        $kp  = self::getKeypairFromUserKey($userKey);
        $dek = sodium_crypto_box_seal_open($sealedDek, $kp);
        if ($dek === false) {
            throw new RuntimeException("Failed to open sealed DEK");
        }

        $plain = CryptoUtils::decrypt($env['d'], $dek);
        CryptoUtils::zeroMemory($dek);
        return $plain;
    }

    /**
     * Encrypts data using a Base64 public key (anonymous encryption).
     */
    public static function sealWithPublicKey(string $plaintext, string $base64PublicKey): string
    {
        $pub = self::decodePublicKey($base64PublicKey);
        return base64_encode(sodium_crypto_box_seal($plaintext, $pub));
    }

    /**
     * Decrypts data sealed with a public key.
     */
    public static function openSealedData(string $sealedBase64, string $userKey): string
    {
        $sealed = base64_decode($sealedBase64, true);
        if ($sealed === false) {
            throw new RuntimeException("Invalid Base64 sealed data");
        }

        $kp    = self::getKeypairFromUserKey($userKey);
        $plain = sodium_crypto_box_seal_open($sealed, $kp);
        if ($plain === false) {
            throw new RuntimeException("Failed to open sealed data");
        }

        return $plain;
    }

    /**
     * Rewraps an envelope (re-seal the DEK to a new userKey).
     */
    public static function rewrapEnvelope(string $envelopeJson, string $oldKey, string $newKey): string
    {
        $env = self::parseEnvelope($envelopeJson);

        $oldSealed = base64_decode($env['k'], true);
        if ($oldSealed === false) {
            throw new InvalidArgumentException("Invalid wrapped-DEK base64");
        }

        $kpOld = self::getKeypairFromUserKey($oldKey);
        $dek   = sodium_crypto_box_seal_open($oldSealed, $kpOld);
        if ($dek === false) {
            throw new RuntimeException("Failed to unwrap DEK");
        }

        $kpNew       = self::getKeypairFromUserKey($newKey);
        $newSealed   = sodium_crypto_box_seal($dek, sodium_crypto_box_publickey($kpNew));
        CryptoUtils::zeroMemory($dek);

        $result = json_encode([
            'd' => $env['d'],
            'k' => base64_encode($newSealed)
        ]);

        if ($result === false) {
            throw new RuntimeException("Failed to encode rewrapped envelope");
        }

        return $result;
    }

    /**
     * Validates and decodes a Base64-encoded public key.
     */
    public static function decodePublicKey(string $base64): string
    {
        $decoded = base64_decode($base64, true);
        if (!is_string($decoded) || strlen($decoded) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException("Public key must be Base64 of " . SODIUM_CRYPTO_BOX_PUBLICKEYBYTES . " bytes.");
        }
        return $decoded;
    }

}

