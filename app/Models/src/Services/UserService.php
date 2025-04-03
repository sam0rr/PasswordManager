<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;
use Zephyrus\Security\Cryptography;

class UserService
{
    private UserBroker $userBroker;
    private EncryptionService $encryptionService;

    public function __construct()
    {
        $this->userBroker = new UserBroker();
        $this->encryptionService = new EncryptionService();
    }

    public function register(Form $form): array
    {
        if (!$this->validateRegisterForm($form)) {
            return $this->buildErrorResponse($form);
        }

        $password = $form->getValue("password");
        $salt = $this->encryptionService->generateSalt();
        $userKey = $this->encryptionService->deriveUserKey($password, $salt);
        $hashedPassword = Cryptography::hashPassword($password);

        $encryptedData = $this->buildEncryptedUserData($form, $hashedPassword, $salt, $userKey);
        $user = $this->userBroker->createUser($encryptedData);

        $this->encryptionService->storeUserContext($user->id, $userKey);

        return $this->buildSuccessRegisterResponse($user, $form);
    }

    public function login(Form $form): array
    {
        if (!$this->validateLoginForm($form)) {
            return $this->buildErrorResponse($form);
        }

        $email = $form->getValue("email");
        $password = $form->getValue("password");

        $user = $this->userBroker->findByEmail($email);
        if (!$user || !Cryptography::verifyHashedPassword($password, $user->password_hash)) {
            return $this->buildInvalidCredentialsResponse();
        }

        $userKey = $this->encryptionService->deriveUserKey($password, $user->salt);
        $user = $this->userBroker->findByEmail($email, $userKey);

        $this->encryptionService->storeUserContext($user->id, $userKey);

        return $this->buildSuccessLoginResponse($user);
    }

    //HELPERS

    private function validateRegisterForm(Form $form): bool
    {
        try {
            UserValidator::assertRegister($form, $this->userBroker);
            return true;
        } catch (FormException) {
            return false;
        }
    }

    private function validateLoginForm(Form $form): bool
    {
        try {
            UserValidator::assertLogin($form);
            return true;
        } catch (FormException) {
            return false;
        }
    }

    private function buildEncryptedUserData(Form $form, string $hashedPassword, string $salt, string $userKey): array
    {
        return [
            'first_name'    => $this->encryptionService->encryptWithUserKey($form->getValue("first_name"), $userKey),
            'last_name'     => $this->encryptionService->encryptWithUserKey($form->getValue("last_name"), $userKey),
            'email'         => $this->encryptionService->encryptWithUserKey($form->getValue("email"), $userKey),
            'phone'         => $this->encryptionService->encryptWithUserKey($form->getValue("phone"), $userKey),
            'image_url'     => $this->encryptionService->encryptWithUserKey($form->getValue("image_url") ?? "", $userKey),
            'email_hash'    => $this->encryptionService->hash256($form->getValue("email")),
            'password_hash' => $hashedPassword,
            'salt'          => $salt
        ];
    }

    private function buildSuccessRegisterResponse($user, Form $form): array
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

    private function buildSuccessLoginResponse($user): array
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

    private function buildInvalidCredentialsResponse(): array
    {
        return [
            "errors" => ["Identifiants invalides."],
            "status" => 401
        ];
    }

    private function buildErrorResponse(Form $form): array
    {
        return [
            "errors" => array_values($form->getErrorMessages()),
            "status" => 400
        ];
    }
}
