<?php

namespace Models\src\Services;

use Controllers\src\Utils\SessionHelper;
use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Services\Utils\BaseService;
use Models\src\Services\Utils\Encryption\EncryptionService;
use Models\src\Services\Utils\Session\SessionContextService;
use Models\src\Validators\AuthValidator;
use Zephyrus\Application\Form;

final class AuthService
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
            return $this->encryption ??= new EncryptionService();
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
        } catch (FormException) {
            return BaseService::buildErrorResponse($form);
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
        } catch (FormException) {
            if (!$isHtmx && $form->getValue("email")) {
                $this->history->logFailure($form->getValue("email"));
            }
            return BaseService::buildErrorResponse($form);
        }
    }

    public function postAuthActions(): void
    {
        if (!$this->currentUserId || !$this->currentUserKey) {
            $this->currentUserKey = SessionContextService::getUserKey();
            $this->currentUserId = SessionContextService::getUserId();
        }
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

        SessionContextService::store($userId, $userKey);
    }

    private function validateUserCredentials(string $email, string $password, Form $form): User
    {
        $user = $this->userBroker->findByEmail($email);

        if (!$user || !$this->encryption->verifyPassword($password, $user->password_hash)) {
            $form->addError("login", "Invalid Credentials.");
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
