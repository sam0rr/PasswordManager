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

    public function register(Form $form, bool $isHtmx): array
    {
        try {
            AuthValidator::assertRegister($form, $this->userBroker, $isHtmx);

            if ($isHtmx) {
                return ["form" => $form];
            }

            $password = $form->getValue("password");
            $salt = $this->encryption->generateSalt();
            $userKey = $this->encryption->deriveUserKey($password, $salt);
            $hashedPassword = $this->encryption->hashPassword($password);

            $encryptedData = $this->buildEncryptedUserData($form, $hashedPassword, $salt, $userKey);
            $user = $this->userBroker->createUser($encryptedData);

            $this->encryption->storeUserContext($user->id, $userKey);

            return ["form" => $form];
        } catch (FormException $e) {
            return ["form" => $e->getForm(), "errors" => true];
        }
    }

    public function login(Form $form, bool $isHtmx): array
    {
        try {
            AuthValidator::assertLogin($form, $isHtmx);

            $email = $form->getValue("email");
            $password = $form->getValue("password");

            $user = $this->validateUserCredentials($email, $password, $form);
            $userKey = $this->encryption->deriveUserKey($password, $user->salt);
            $user = $this->userBroker->findByEmail($email, $userKey);

            if ($isHtmx) {
                return ["form" => $form];
            }

            $this->encryption->storeUserContext($user->id, $userKey);
            $this->acceptUserPendingShares($user->id, $userKey);
            $this->history->logSuccess($user);

            return ["form" => $form];
        } catch (FormException $e) {
            $this->history->logFailure($form->getValue("email"));
            return ["form" => $e->getForm(), "errors" => true];
        }
    }

    // Helpers...

    private function acceptUserPendingShares(string $userId, string $userKey): void
    {
        (new SharingService(['user_id' => $userId, 'user_key' => $userKey]))->acceptPendingShares();
    }

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
}
