<?php

namespace Models\src\Services;



namespace Models\src\Services;

use Zephyrus\Core\Session;
use Zephyrus\Security\Cryptography;

class EncryptionService
{
    public function deriveUserKey(string $password, string $salt): string
    {
        return Cryptography::deriveEncryptionKey($password, $salt);
    }

    public function storeUserKeyInSession(string $userKey): void
    {
        Session::set("user_encryption_key", $userKey);
    }

    public function getUserKeyFromSession(): ?string
    {
        return Session::get("user_encryption_key");
    }

    public function encryptWithUserKey(string $data, string $userKey): string
    {
        return Cryptography::encrypt($data, $userKey);
    }

    public function decryptWithUserKey(string $cipherText, string $userKey): ?string
    {
        return Cryptography::decrypt($cipherText, $userKey);
    }

    public function hash256(string $data): string
    {
        return Cryptography::hash($data, 'sha256');
    }

    public function generateSalt(int $length = 32): string
    {
        return Cryptography::randomHex($length);
    }
}
