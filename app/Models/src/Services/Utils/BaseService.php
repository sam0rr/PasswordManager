<?php

namespace Models\src\Services\Utils;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Entities\UserPassword;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\EncryptionService;
use Models\src\Services\SharingService;
use Zephyrus\Application\Form;

abstract class BaseService
{
    protected PasswordBroker $passwordBroker;
    protected UserBroker $userBroker;
    protected EncryptionService $encryption;
    protected AuthHistoryService $history;
    protected array $auth;
    protected SharingService $sharing;
    protected AvatarService $avatar;

    protected function buildErrorResponse(Form $form): array
    {
        return [
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

    protected function getPassword(string $passwordId, Form $form): UserPassword
    {
        $password = $this->passwordBroker->findById($passwordId, $this->auth['user_key']);

        if (!$password || $password->user_id !== $this->auth['user_id']) {
            $form->addError('global', "Mot de passe introuvable ou non autorisé.");
            throw new FormException($form);
        }

        return $password;
    }

}
