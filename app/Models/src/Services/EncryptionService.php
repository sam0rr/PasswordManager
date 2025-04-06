<?php

namespace Models\src\Services;

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
        return $this->hash256($userKey);
    }

    public static function destroySession(): void
    {
        Session::destroy();
    }

}
