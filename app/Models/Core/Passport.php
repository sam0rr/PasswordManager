<?php namespace Models\Core;

use stdClass;
use Zephyrus\Core\Session;
use Zephyrus\Security\Cryptography;

final class Passport
{
    /**
     * Verifies if there is a user currently authenticated in the application.
     *
     * @return bool
     */
    public static function isAuthenticated(): bool
    {
        $user = Session::get('user');
        return !is_null($user);
    }

    /**
     * Retrieves the entire instance of the authenticated user (if any). Returns null if no user has been
     * authenticated.
     *
     * @return stdClass|null
     */
    public static function getUser(): ?stdClass
    {
        $user = Session::get('user');
        if (is_null($user)) {
            return null;
        }
        return clone $user;
    }

    /**
     * Shortcut method to retrieve the authenticated user id or null otherwise.
     *
     * @return int|null
     */
    public static function getUserId(): ?int
    {
        $user = self::getUser();
        if (is_null($user)) {
            return null;
        }
        return $user->id;
    }

    public static function isSuperuser(): bool
    {
        $user = self::getUser();
        if (is_null($user)) {
            return false;
        }
        return $user->superuser;
    }

    /**
     * Verifies if the given password matches the one of the authenticated user. Useful for operation that should be
     * password protected.
     *
     * @param string $password
     * @return bool
     */
    public static function passwordMatch(string $password): bool
    {
        $user = self::getUser();
        if (is_null($user)) {
            return false;
        }
        return Cryptography::verifyHashedPassword($password, $user->password_hash);
    }

    /**
     * Registers the given user into session as the Passport authenticated user.
     *
     * @param stdClass $user
     * @return void
     */
    public static function registerUser(stdClass $user): void
    {
        session(['user' => $user]);
    }
}
