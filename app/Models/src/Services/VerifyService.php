<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\VerifyBroker;
use Models\src\Entities\UserVerify;
use Models\src\Services\Mfa\AuthenticatorMfaService;
use Models\src\Services\Utils\BaseService;
use RuntimeException as RuntimeExceptionAlias;
use Zephyrus\Application\Form;

class VerifyService extends BaseService
{
    private ?VerifyBroker $verifyBroker = null {
        get {
            return $this->verifyBroker ??= new VerifyBroker($this->encryption);
        }
    }
    private ?AuthenticatorMfaService $authenticatorMfaService = null {
        get {
            return $this->authenticatorMfaService ??= new AuthenticatorMfaService($this->auth);
        }
    }

    private const int MFA_EXPIRATION_SECONDS = 300;

    public function handleActivation(Form $form): UserVerify
    {
        $method = $this->extractMethodOrFail($form);
        return $this->activateMethod($method);
    }

    public function handleDeactivation(Form $form): void
    {
        $method = $this->extractMethodOrFail($form);
        $this->disableMethod($method);
    }

    public function activateMethod(string $method): UserVerify
    {
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];
        $existing = $this->verifyBroker->findByMethod($userId, $method, $userKey);

        if (!$existing) {
            $verify = $this->verifyBroker->createMethod(
                $this->buildEncryptedVerifyData($userId, $method), $userKey
            );
        } else {
            $this->verifyBroker->activate($userId, $method, $userKey);
            $verify = $this->verifyBroker->findByMethod($userId, $method, $userKey);
        }

        $this->updateMfaCount();
        return $verify;
    }

    public function disableMethod(string $method): void
    {
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];

        if ($userId) {
            $this->verifyBroker->deactivate($userId, $method, $userKey);
            $this->updateMfaCount();
        }
    }

    public function updateSecret(string $userId, string $method, string $otp): void
    {
        $encryptedOtp = $this->encryption->encryptWithUserKey($otp, $this->auth['user_key']);
        $this->verifyBroker->updateSecret($userId, $method, $encryptedOtp);
    }

    public function markVerified(string $method): void
    {
        $userKey = $this->auth['user_key'];
        $userId = $this->auth['user_id'];

        if ($userId) {
            $this->verifyBroker->updateLastVerified($userId, $method, $userKey);
        }
    }

    public function getAllMethods(): array
    {
        $userKey = $this->auth['user_key'];
        $userId = $this->auth['user_id'];

        return $this->verifyBroker->findAllByUser($userId, $userKey);
    }

    public function areAllMethodsVerified(): bool
    {
        $methods = $this->getAllMethods();
        return array_all($methods, fn($method) => !$method->is_active || $this->isMethodVerified($method));
    }

    public function getPendingMethods(): array
    {
        return array_filter($this->getAllMethods(), function (UserVerify $method) {
            return $method->is_active && !$this->isMethodVerified($method);
        });
    }

    public function getMethod(string $method): ?UserVerify
    {
        $userKey = $this->auth['user_key'];
        $userId = $this->auth['user_id'];

        return $userId ? $this->verifyBroker->findByMethod($userId, $method, $userKey) : null;
    }

    public function isMethodVerified(UserVerify $method): bool
    {
        if (empty($method->last_verified)) {
            return false;
        }

        $lastVerified = strtotime($method->last_verified);
        return ($lastVerified + self::MFA_EXPIRATION_SECONDS) >= time();
    }

    public function getUserEmail(): string
    {
        return $this->userBroker
            ->findById($this->auth['user_id'], $this->auth['user_key'])
            ->email;
    }

    public function getUserPhone(): string
    {
        return $this->userBroker
            ->findById($this->auth['user_id'], $this->auth['user_key'])
            ->phone;
    }

    // Helpers

    private function extractMethodOrFail(Form $form): string
    {
        $method = $form->getValue('method');
        if (empty($method)) {
            $form->addError("global", "La méthode est requise.");
            throw new FormException($form);
        }
        return $method;
    }

    private function updateMfaCount(): void
    {
        $count = count(array_filter($this->getAllMethods(), fn($m) => $m->is_active));
        $this->userBroker->updateMfaCount($this->auth['user_id'], $count);
    }

    private function buildEncryptedVerifyData(string $userId, string $method): array
    {
        $otp = $this->getOtpForMethod($method);

        return [
            'user_id' => $userId,
            'method' => $method,
            'otp_secret' => $this->encryption->encryptWithUserKey($otp, $this->auth['user_key']),
            'last_verified' => date('Y-m-d H:i:s', strtotime('-1 day')),
            'is_active' => true
        ];
    }

    private function getOtpForMethod(string $method): string
    {
        return match ($method) {
            'authenticator' => $this->authenticatorMfaService->generateSecret(),
            'mail', 'sms' => '000000',
            default => throw new RuntimeExceptionAlias("Méthode MFA inconnue: $method")
        };
    }

}
