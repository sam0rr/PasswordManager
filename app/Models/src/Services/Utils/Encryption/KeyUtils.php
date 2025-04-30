<?php

namespace Models\src\Services\Utils\Encryption;

use InvalidArgumentException;
use RuntimeException;
use Zephyrus\Security\Cryptography;

class KeyUtils
{
    /**
     * From a hex-encoded userKey, build a keypair.
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
     * Derive the Base64 public key from the hex userKey.
     */
    public static function generatePublicKeyFromUserKey(string $userKey): string
    {
        $kp  = (new KeyUtils)->getKeypairFromUserKey($userKey);
        $pub = sodium_crypto_box_publickey($kp);
        return base64_encode($pub);
    }

    /**
     * Envelope-encrypt:
     * 1) Rncrypt plaintext under a random DEK (via Cryptography::encrypt)
     * 2) seal that DEK under the user’s public key
     * 3) return JSON { d: <base64 ciphertext>, k: <base64 wrapped DEK> }
     */
    public static function encryptEnvelope(string $plaintext, string $userKey): string
    {
        $dek    = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $cipher = Cryptography::encrypt($plaintext, bin2hex($dek));

        $kp      = (new KeyUtils)->getKeypairFromUserKey($userKey);
        $wrapped = sodium_crypto_box_seal($dek, sodium_crypto_box_publickey($kp));

        return json_encode([
            'd' => base64_encode($cipher),
            'k' => base64_encode($wrapped)
        ]);
    }

    /**
     * Envelope-decrypt:
     * 1) parse JSON envelope
     * 2) base64-decode wrapped DEK & seal
     * 3) open DEK via userKey
     * 4) decrypt payload via Cryptography::decrypt
     */
    public static function decryptEnvelope(string $envelopeJson, string $userKey): ?string
    {
        $env = json_decode($envelopeJson, true);
        if (!isset($env['d'], $env['k'])) {
            throw new InvalidArgumentException("Invalid envelope format");
        }
        $cipher     = base64_decode($env['d'], true);
        $wrappedDek = base64_decode($env['k'], true);
        if ($cipher === false || $wrappedDek === false) {
            throw new RuntimeException("Malformed base64 in envelope");
        }

        $dek = self::unwrapDek($wrappedDek, $userKey);
        return Cryptography::decrypt($cipher, bin2hex($dek));
    }

    /**
     * Wraps a raw DEK under a recipient’s Base64 public key.
     */
    public static function sealWithPublicKey(string $plaintext, string $base64PublicKey): string
    {
        $pub = self::decodePublicKey($base64PublicKey);
        return base64_encode(sodium_crypto_box_seal($plaintext, $pub));
    }

    /**
     * Opens data sealed to this user’s keypair (derived from userKey).
     */
    public static function openSealedData(string $sealedBase64, string $userKey): string
    {
        $sealed = base64_decode($sealedBase64, true);
        if ($sealed === false) {
            throw new RuntimeException("Invalid Base64 sealed data");
        }
        $kp    = (new KeyUtils)->getKeypairFromUserKey($userKey);
        $plain = sodium_crypto_box_seal_open($sealed, $kp);
        if ($plain === false) {
            throw new RuntimeException("Failed to open sealed data");
        }
        return $plain;
    }

    /**
     * Unwraps a sealed DEK using the userKey-derived keypair.
     */
    public static function unwrapDek(string $wrappedDek, string $userKey): string
    {
        $kp  = (new KeyUtils)->getKeypairFromUserKey($userKey);
        $dek = sodium_crypto_box_seal_open($wrappedDek, $kp);
        if ($dek === false) {
            throw new RuntimeException("Failed to unwrap DEK");
        }
        return $dek;
    }

    /**
     * Re-envelops an existing JSON envelope under a new userKey.
     */
    public static function rewrapEnvelope(string $envelopeJson, string $oldKey, string $newKey): string
    {
        $env = json_decode($envelopeJson, true);
        if (!isset($env['d'], $env['k'])) {
            throw new InvalidArgumentException("Invalid envelope format");
        }
        $wrappedDek = base64_decode($env['k'], true);
        if ($wrappedDek === false) {
            throw new InvalidArgumentException("Invalid wrapped-DEK base64");
        }

        $dek      = self::unwrapDek($wrappedDek, $oldKey);
        $newPub   = sodium_crypto_box_publickey((new KeyUtils)->getKeypairFromUserKey($newKey));
        $newWrapped = sodium_crypto_box_seal($dek, $newPub);

        return json_encode([
            'd' => $env['d'],
            'k' => base64_encode($newWrapped)
        ]);
    }

    /**
     * Validates & decodes a Base64 public key.
     */
    public static function decodePublicKey(string $base64): string
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
