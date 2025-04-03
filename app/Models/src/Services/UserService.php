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
        try {
            UserValidator::assertRegister($form, $this->userBroker);
        } catch (FormException $e) {
            return ["errors" => array_values($e->getForm()->getErrorMessages()), "status" => 400];
        }

        $salt = $this->encryptionService->generateSalt();
        $clearPassword = $form->getValue("password");
        $hashedPassword = Cryptography::hashPassword($clearPassword);
        $userKey = $this->encryptionService->deriveUserKey($clearPassword, $salt);

        $encryptedEmail = $this->encryptionService->encryptWithUserKey($form->getValue("email"), $userKey);
        $encryptedPhone = $this->encryptionService->encryptWithUserKey($form->getValue("phone"), $userKey);
        $encryptedFirstName = $this->encryptionService->encryptWithUserKey($form->getValue("first_name"), $userKey);
        $encryptedLastName = $this->encryptionService->encryptWithUserKey($form->getValue("last_name"), $userKey);
        $encryptedImage = $this->encryptionService->encryptWithUserKey($form->getValue("image_url") ?? "", $userKey);
        $emailHash = $this->encryptionService->hash256($form->getValue("email"));

        $user = $this->userBroker->createUser([
            'first_name' => $encryptedFirstName,
            'last_name' => $encryptedLastName,
            'email' => $encryptedEmail,
            'phone' => $encryptedPhone,
            'image_url' => $encryptedImage,
            'email_hash' => $emailHash,
            'password_hash' => $hashedPassword,
            'salt' => $salt
        ]);

        $this->encryptionService->storeUserContext($user->id, $userKey);

        return [
            "message" => "Compte créé avec succès",
            "user" => [
                "id" => $user->id,
                "email" => $form->getValue("email"),
                "firstName" => $form->getValue("first_name"),
                "lastName" => $form->getValue("last_name")
            ],
            "status" => 201
        ];
    }

    public function login(Form $form): array
    {
        try {
            UserValidator::assertLogin($form);
        } catch (FormException $e) {
            return ["errors" => array_values($e->getForm()->getErrorMessages()), "status" => 400];
        }

        $clearPassword = $form->getValue("password");
        $email = $form->getValue("email");

        $user = $this->userBroker->findByEmail($email);
        if (!$user || !Cryptography::verifyHashedPassword($clearPassword, $user->password_hash)) {
            return ["errors" => ["Identifiants invalides."], "status" => 401];
        }

        $userKey = $this->encryptionService->deriveUserKey($clearPassword, $user->salt);
        $this->encryptionService->storeUserContext($user->id, $userKey);

        return [
            "message" => "Connexion réussie",
            "user" => [
                "id" => $user->id,
                "email" => $email
            ],
            "status" => 200
        ];
    }
}
