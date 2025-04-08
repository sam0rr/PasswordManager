<?php

namespace Models\src\Services;

use InvalidArgumentException;
use RuntimeException;
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
        $binaryPrivateKey = $this->extractPrivateKey($userKey, SODIUM_CRYPTO_SCALARMULT_BYTES);
        return base64_encode(sodium_crypto_scalarmult_base($binaryPrivateKey));
    }

    public function encryptWithPublicKey(string $plainText, string $base64PublicKey): string
    {
        $publicKey = $this->decodePublicKey($base64PublicKey);
        return base64_encode(sodium_crypto_box_seal($plainText, $publicKey));
    }

    public function decryptFromPublicKey(string $base64CipherText, string $base64PublicKey, string $userKey): ?string
    {
        $privateKey = $this->extractPrivateKey($userKey, SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
        $publicKey = $this->decodePublicKey($base64PublicKey);
        $sealed = base64_decode($base64CipherText);

        if ($sealed === false) {
            throw new RuntimeException("Invalid base64 ciphertext.");
        }

        $keyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey($privateKey, $publicKey);
        $plaintext = sodium_crypto_box_seal_open($sealed, $keyPair);

        if ($plaintext === false) {
            throw new RuntimeException("Decryption failed: invalid message or mismatched keys.");
        }

        return $plaintext;
    }

    private function extractPrivateKey(string $userKey, int $expectedLength): string
    {
        $binary = hex2bin(mb_substr($userKey, 0, 64));

        if ($binary === false || strlen($binary) !== $expectedLength) {
            throw new InvalidArgumentException("Invalid private key format.");
        }

        return $binary;
    }

    private function decodePublicKey(string $base64): string
    {
        $decoded = base64_decode($base64);
        if ($decoded === false || strlen($decoded) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException("Invalid public key format.");
        }

        return $decoded;
    }

    public static function destroySession(): void
    {
        Session::destroy();
    }

}
