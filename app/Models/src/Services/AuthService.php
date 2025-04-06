<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\AuthValidator;
use Zephyrus\Application\Form;

class AuthService extends BaseService
{
    public function __construct()
    {
        $this->userBroker = new UserBroker();
        $this->history = new AuthHistoryService();
        $this->encryption = new EncryptionService();
    }

    public function register(Form $form, $isHtmx): array
    {
        try {
            AuthValidator::assertRegister($form, $this->userBroker, $isHtmx);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "status" => 200
                ];
            }

            $password = $form->getValue("password");
            $salt = $this->encryption->generateSalt();
            $userKey = $this->encryption->deriveUserKey($password, $salt);
            $hashedPassword = $this->encryption->hashPassword($password);

            $encryptedData = $this->buildEncryptedUserData($form, $hashedPassword, $salt, $userKey);
            $user = $this->userBroker->createUser($encryptedData);

            $this->encryption->storeUserContext($user->id, $userKey);

            return $this->buildSuccessRegisterResponse($user, $form);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function login(Form $form, $isHtmx): array
    {
        try {
            AuthValidator::assertLogin($form, $isHtmx);

            $email = $form->getValue("email");
            $password = $form->getValue("password");

            $user = $this->validateUserCredentials($email, $password, $form);
            $userKey = $this->encryption->deriveUserKey($password, $user->salt);
            $user = $this->userBroker->findByEmail($email, $userKey);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "status" => 200
                ];
            }

            $this->encryption->storeUserContext($user->id, $userKey);

            $this->history->logSuccess($user);

            return $this->buildSuccessLoginResponse($user);
        } catch (FormException) {
            $this->history->logFailure($form->getValue("email"));
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function validateUserCredentials(string $email, string $password, Form $form): User
    {
        $user = $this->userBroker->findByEmail($email);

        if (!$user || !$this->encryption->verifyPassword($password, $user->password_hash)) {
            $form->addError("login", "Identifiants invalides.");
            throw new FormException($form);
        }

        return $user;
    }

    private function buildEncryptedUserData(Form $form, string $hashedPassword, string $salt, string $userKey): array
    {
        return [
            'first_name'    => $this->encryption->encryptWithUserKey($form->getValue("first_name"), $userKey),
            'last_name'     => $this->encryption->encryptWithUserKey($form->getValue("last_name"), $userKey),
            'email'         => $this->encryption->encryptWithUserKey($form->getValue("email"), $userKey),
            'phone'         => $this->encryption->encryptWithUserKey($form->getValue("phone"), $userKey),
            'image_url'     => $this->encryption->encryptWithUserKey($form->getValue("image_url") ?? "", $userKey),
            'email_hash'    => $this->encryption->hash256($form->getValue("email")),
            'password_hash' => $hashedPassword,
            'salt'          => $salt,
            'public_key'    => $this->encryption->generatePublicKey($userKey),
        ];
    }

    private function buildSuccessRegisterResponse(User $user, Form $form): array
    {
        return [
            "message" => "Compte créé avec succès",
            "user" => [
                "id"        => $user->id,
                "email"     => $form->getValue("email"),
                "firstName" => $form->getValue("first_name"),
                "lastName"  => $form->getValue("last_name")
            ],
            "status" => 201
        ];
    }

    private function buildSuccessLoginResponse(User $user): array
    {
        return [
            "message" => "Connexion réussie",
            "user" => [
                "id"    => $user->id,
                "email" => $user->email
            ],
            "status" => 200
        ];
    }
}
