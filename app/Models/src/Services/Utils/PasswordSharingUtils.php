<?php

namespace Models\src\Services\Utils;

use RuntimeException;

class PasswordSharingUtils
{
    public static function encodeInfo(string $emailFrom, string $password, string $description, string $note): string
    {
        return json_encode([
            'email_from' => $emailFrom,
            'password' => $password,
            'description' => $description,
            'note' => $note
        ]);
    }

    public static function decodeInfo(string $json): array
    {
        $decoded = json_decode($json, true);

        if (!is_array($decoded) || !isset($decoded['email_from'], $decoded['password'], $decoded['description'], $decoded['note'])) {
            throw new RuntimeException('Invalid encrypted_info format.');
        }

        return $decoded;
    }

}
