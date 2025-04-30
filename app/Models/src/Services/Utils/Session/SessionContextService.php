<?php

namespace Models\src\Services\Utils\Session;

use RuntimeException;
use Zephyrus\Core\Session;
use Zephyrus\Security\Cryptography;

final class SessionContextService
{
    private const string CONTEXT_KEY = 'user_context';

    private static ?array $cachedContext = null;

    public static function store(string $userId, string $userKey): void
    {
        $payload = json_encode([
            'user_id' => $userId,
            'key'     => bin2hex($userKey)
        ]);

        $encrypted = Cryptography::encrypt($payload);
        Session::set(self::CONTEXT_KEY, $encrypted);
        self::$cachedContext = null;
    }

    public static function destroy(): void
    {
        Session::destroy();
        self::$cachedContext = null;
    }

    public static function isAuthenticated(): bool
    {
        try {
            $ctx = self::get();
            return !empty($ctx['user_id']) && !empty($ctx['key']);
        } catch (RuntimeException) {
            return false;
        }
    }

    public static function getUserId(): ?string
    {
        try {
            return self::get()['user_id'];
        } catch (RuntimeException) {
            return null;
        }
    }

    public static function getUserKey(): ?string
    {
        try {
            return self::get()['key'];
        } catch (RuntimeException) {
            return null;
        }
    }

    private static function get(): array
    {
        if (self::$cachedContext !== null) {
            return self::$cachedContext;
        }

        $enc = Session::get(self::CONTEXT_KEY);
        if ($enc === null) {
            throw new RuntimeException("No user context in session");
        }

        $json = Cryptography::decrypt($enc);
        $data = json_decode($json, true);

        if (!is_array($data) || !isset($data['user_id'], $data['key'])) {
            throw new RuntimeException("Invalid session context");
        }

        return self::$cachedContext = $data;
    }

}

