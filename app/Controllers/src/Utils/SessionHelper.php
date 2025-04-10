<?php

namespace Controllers\src\Utils;

use Zephyrus\Application\Form;
use Zephyrus\Core\Session;

class SessionHelper
{
    public static function setContext(array $data): void
    {
        $defaults = [
            "user" => null,
            "form" => new Form(),
            "title" => "Tableau de bord",
            "stats" => [],
            "passwords" => [],
            "shared_passwords" => [],
            "auth_history" => [],
            "shared_credentials" => [],
            "passwordsUnlocked" => false,
            "activeSection" => "profile",
            "tab" => "info"
        ];

        Session::setAll(array_merge($defaults, $data));
    }

    public static function getContext(): array
    {
        return [
            "user" => Session::get("user"),
            "form" => Session::get("form"),
            "passwords" => Session::get("passwords", []),
            "passwordsUnlocked" => Session::get("passwordsUnlocked", false),
            "shared_credentials" => Session::get("shared_credentials", []),
            "shared_passwords" => Session::get("shared_passwords", []),
            "auth_history" => Session::get("auth_history", []),
            "stats" => Session::get("stats", []),
            "activeSection" => $_GET['section'] ?? Session::get('activeSection', 'profile'),
            "tab" => $_GET['tab'] ?? Session::get('tab', 'info')
        ];
    }

    public static function appendContext(array $data): void
    {
        foreach ($data as $key => $value) {
            Session::set($key, $value);
        }
    }

    public static function clearContext(): void
    {
        Session::removeAll([
            "user", "form", "title", "stats", "passwords", "shared_passwords",
            "auth_history", "shared_credentials", "passwordsUnlocked",
            "activeSection", "tab"
        ]);
    }
}
