<?php

namespace Models\src\Services;

use Controllers\src\Utils\SessionHelper;
use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\AuthValidator;
use Zephyrus\Application\Form;

class AuthService
{
    private ?string $currentUserId = null;
    private ?string $currentUserKey = null;

    private ?UserBroker $userBroker = null {
        get {
            return $this->userBroker ??= new UserBroker($this->encryption);
        }
    }
    private ?SharingService $sharingService = null {
        get {
            return $this->sharingService ??= new SharingService($this->getAuth());
        }
    }
    private ?EncryptionService $encryption = null {
        get {
            return $this->encryption ??= new EncryptionService($this->getAuth());
        }
    }
    private ?AuthHistoryService $history = null {
        get {
            return $this->history ??= new AuthHistoryService($this->getAuth());
        }
    }
    private ?VerifyService $verifyService = null {
        get {
            return $this->verifyService ??= new VerifyService($this->getAuth());
        }
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

            $this->storeAuthContext($user->id, $userKey);

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

            $this->storeAuthContext($user->id, $userKey);


            if ($this->verifyService->hasPendingMfa()) {
                SessionHelper::append(['mfa_validated' => false]);
                return ["form" => $form];
            }

            $this->postAuthActions();
            SessionHelper::append(['mfa_validated' => true]);

            return ["form" => $form];
        } catch (FormException $e) {
            if (!$isHtmx && $form->getValue("email")) {
                $this->history->logFailure($form->getValue("email"));
            }
            return ["form" => $e->getForm(), "errors" => true];
        }
    }

    public function postAuthActions(): void
    {
        $user = $this->userBroker->findById($this->currentUserId, $this->currentUserKey);

        $this->sharingService->acceptPendingShares();
        $this->history->logSuccess($user);
    }

    // Helpers

    public function getAuth(): array
    {
        return [
            'user_id' => $this->currentUserId,
            'user_key' => $this->currentUserKey
        ];
    }

    private function storeAuthContext(string $userId, string $userKey): void
    {
        $this->currentUserId = $userId;
        $this->currentUserKey = $userKey;

        $this->encryption->storeUserContext($userId, $userKey);
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
        $e = $this->encryption;

        return [
            'first_name'    => $e->encryptWithUserKey($form->getValue("first_name"), $userKey),
            'last_name'     => $e->encryptWithUserKey($form->getValue("last_name"), $userKey),
            'email'         => $e->encryptWithUserKey($form->getValue("email"), $userKey),
            'phone'         => $e->encryptWithUserKey($form->getValue("phone"), $userKey),
            'image_url'     => $e->encryptWithUserKey($form->getValue("image_url") ?? "/assets/images/default-avatar.png", $userKey),
            'email_hash'    => $e->hash256(strtolower($form->getValue("email"))),
            'password_hash' => $hashedPassword,
            'salt'          => $salt,
            'public_key'    => $e->generatePublicKey($userKey),
        ];
    }

}
