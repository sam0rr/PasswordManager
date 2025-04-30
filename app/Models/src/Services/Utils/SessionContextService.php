<?php

namespace Models\src\Services\Utils;

use RuntimeException;
use Zephyrus\Core\Session;
use Zephyrus\Security\Cryptography;

final class SessionContextService
{
    /**
     * Session key used to store the encrypted user context.
     */
    private const string CONTEXT_KEY = 'user_context';

    /**
     * Cache of the decrypted session blob so we only decrypt once per request.
     */
    private static ?array $cachedContext = null;

    /**
     * Encrypts and stores [user_id + userKey] in session.
     */
    public static function store(string $userId, string $userKey): void
    {
        $payload = json_encode([
            'user_id' => $userId,
            'key'     => $userKey
        ]);
        Session::set(self::CONTEXT_KEY, Cryptography::encrypt($payload));
        self::$cachedContext = null;
    }

    /**
     * Clears the entire session and cached context.
     */
    public static function destroy(): void
    {
        Session::destroy();
        self::$cachedContext = null;
    }

    /**
     * Checks if both user ID and user key are present and valid.
     */
    public static function isAuthenticated(): bool
    {
        try {
            $ctx = self::get();
            return !empty($ctx['user_id']) && !empty($ctx['key']);
        } catch (RuntimeException) {
            return false;
        }
    }

    /**
     * Retrieves the user_id from the encrypted session payload.
     */
    public static function getUserId(): ?string
    {
        try {
            return self::get()['user_id'];
        } catch (RuntimeException) {
            return null;
        }
    }

    /**
     * Retrieves the userKey (hex) from the encrypted session payload.
     */
    public static function getUserKey(): ?string
    {
        try {
            return self::get()['key'];
        } catch (RuntimeException) {
            return null;
        }
    }

    /**
     * Internal: decrypts and parses the session blob exactly once.
     *
     * @throws RuntimeException if session value is missing or malformed
     */
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

