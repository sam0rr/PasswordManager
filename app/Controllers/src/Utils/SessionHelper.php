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
            "title" => "Tableau de bord",
            "passwords" => [],
            "shared_credentials" => [],
            "auth_history" => [],
            "security_analysis" => [],
            "security_password_fingerprint" => [],
            "activeSection" => "profile",
            "tab" => "info",
        ];

        Session::setAll(array_merge($defaults, $data));
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        return Session::get($key, $default);
    }

    public static function getContext(): array
    {
        return [
            "title" => Session::get("title"),
            "user" => Session::get("user"),
            "form" => new Form(),
            "passwords" => Session::get("passwords", []),
            "shared_credentials" => Session::get("shared_credentials", []),
            "auth_history" => Session::get("auth_history", []),
            "security_analysis" => Session::get("security_analysis", []),
            "security_password_fingerprint" => Session::get("security_password_fingerprint", []),
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

    public static function setForm(string $key, Form $form): void
    {
        Session::set("form__{$key}", [
            'values' => $form->getFields(),
            'errors' => $form->getErrors()
        ]);
    }

    public static function getForm(?string $key = null): Form
    {
        $form = new Form();

        if (is_null($key)) {
            return $form;
        }

        $stored = Session::get("form__{$key}");
        if (!is_array($stored)) {
            return $form;
        }

        foreach ($stored['values'] ?? [] as $field => $value) {
            $form->addField($field, $value);
        }

        foreach ($stored['errors'] ?? [] as $field => $messages) {
            foreach ((array) $messages as $message) {
                $form->addError($field, $message);
            }
        }

        return $form;
    }

    public static function clearForm(string $key): void
    {
        Session::remove("form__{$key}");
    }

}