<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\AuthBroker;
use Models\src\Validators\AuthValidator;
use Zephyrus\Application\Form;
use Zephyrus\Security\Cryptography;

class AuthService
{
    private AuthBroker $userBroker;
    private EncryptionService $encryptionService;

    public function __construct()
    {
        $this->userBroker = new AuthBroker();
        $this->encryptionService = new EncryptionService();
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
            $salt = $this->encryptionService->generateSalt();
            $userKey = $this->encryptionService->deriveUserKey($password, $salt);
            $hashedPassword = Cryptography::hashPassword($password);

            $encryptedData = $this->buildEncryptedUserData($form, $hashedPassword, $salt, $userKey);
            $user = $this->userBroker->createUser($encryptedData);

            $this->encryptionService->storeUserContext($user->id, $userKey);

            return $this->buildSuccessRegisterResponse($user, $form);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function login(Form $form): array
    {
        try {
            AuthValidator::assertLogin($form);

            $email = $form->getValue("email");
            $password = $form->getValue("password");

            $user = $this->userBroker->findByEmail($email);
            if (!$user || !Cryptography::verifyHashedPassword($password, $user->password_hash)) {
                $form->addError("login", "Identifiants invalides.");
                return $this->buildErrorResponse($form);
            }

            $userKey = $this->encryptionService->deriveUserKey($password, $user->salt);
            $user = $this->userBroker->findByEmail($email, $userKey);

            $this->encryptionService->storeUserContext($user->id, $userKey);

            return $this->buildSuccessLoginResponse($user);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

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

    private function buildErrorResponse(Form $form): array
    {
        return [
            "errors" => $form->getErrorMessages(),
            "form" => $form,
            "status" => 400
        ];
    }
}