<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Zephyrus\Application\Form;

abstract class BaseService
{
    protected PasswordBroker $passwordBroker;
    protected UserBroker $userBroker;
    protected EncryptionService $encryption;
    protected array $auth;

    protected function buildErrorResponse(Form $form): array
    {
        return [
            "status" => 400,
            "errors" => $form->getErrorMessages(),
            "form" => $form
        ];
    }

    protected function getAuthenticatedUser(string $password, Form $form): User
    {
        $user = $this->userBroker->findById($this->auth['user_id']);

        if (!$user || !$this->encryption->verifyPassword($password, $user->password_hash)) {
            $form->addError("global", "Mot de passe invalide.");
            throw new FormException($form);
        }

        return $user;
    }

    protected function verifyTempKey(string $password, string $salt, Form $form): void
    {
        $derivedKey = $this->encryption->deriveUserKey($password, $salt);

        if (!hash_equals($derivedKey, $this->auth['user_key'])) {
            $form->addError("global", "La clé dérivée ne correspond pas au contexte actif.");
            throw new FormException($form);
        }
    }

    protected function isValidUuid(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid);
    }
}
