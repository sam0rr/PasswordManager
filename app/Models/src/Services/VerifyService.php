<?php

namespace Models\src\Services;

use Controllers\src\Utils\SessionHelper;
use Models\Exceptions\FormException;
use Models\src\Brokers\VerifyBroker;
use Models\src\Entities\UserVerify;
use Models\src\Services\Mfa\AuthenticatorMfaService;
use Models\src\Services\Utils\BaseService;
use Models\src\Validators\VerifyValidator;
use RuntimeException as RuntimeExceptionAlias;
use Throwable as ThrowableAlias;
use Zephyrus\Application\Form;

class VerifyService extends BaseService
{
    private const int MFA_EXPIRATION_SECONDS = 300; //5 MINUTES
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
    private ?AuthService $authService = null {
        get {
            return $this->authService ??= new AuthService();
        }
    }

    public function getAllMethods(): array
    {
        try {
            $userId = $this->auth['user_id'];
            $userKey = $this->auth['user_key'];

            return $this->verifyBroker->findAllByUser($userId, $userKey);
        } catch (ThrowableAlias) {
            return [];
        }
    }

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

    public function confirmCode(Form $form, $service, bool $isHtmx): array
    {
        try {
            $userId = $this->auth['user_id'];

            VerifyValidator::assertConfirm($form, $isHtmx);

            $method = $form->getValue('method');
            $code = $form->getValue('code');

            $isValid = $service->verifyCode($userId, $code);

            if (!$isValid && !empty($code)) {
                $form->addError('code', 'Code incorrect ou expiré.');
                throw new FormException($form);
            }

            if ($isHtmx) {
                return [
                    "form" => $form
                ];
            }

            $this->markVerified($method);
            $this->handlePostMfaActions();

            return [
                'form' => $form,
                'method' => $method
            ];
        } catch (FormException) {
            return ['form' => $form];
        }
    }

    // Helpers

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

        return $verify;
    }

    public function disableMethod(string $method): void
    {
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];

        if ($userId) {
            $this->verifyBroker->deactivate($userId, $method, $userKey);
        }
    }

    public function updateSecret(string $userId, string $method, string $otp): void
    {
        $encryptedOtp = $this->encryption->encryptWithUserKey($otp, $this->auth['user_key']);
        $this->verifyBroker->updateSecret($userId, $method, $encryptedOtp);
    }

    public function handlePostMfaActions(): void
    {
        if (!$this->areAllMethodsVerified()) {
            return;
        }

        $this->authService->postAuthActions();

        SessionHelper::append([
            'mfa_validated' => true
        ]);
    }

    public function markVerified(string $method): void
    {
        $userKey = $this->auth['user_key'];
        $userId = $this->auth['user_id'];

        if ($userId) {
            $this->verifyBroker->updateLastVerified($userId, $method, $userKey);
        }
    }

    public function areAllMethodsVerified(): bool
    {
        $methods = $this->getAllMethods();
        return array_all($methods, fn($method) => !$method->is_active || $this->isMethodVerified($method));
    }

    public function hasPendingMfa(): bool
    {
        return !empty($this->getPendingMethods());
    }

    public function getPendingMethods(): array
    {
        return array_filter($this->getAllMethods(), function (UserVerify $method) {
            return $method->is_active && !$this->isMethodVerified($method);
        });
    }

    public function isMethodVerified(UserVerify $method): bool
    {
        if (empty($method->last_verified)) {
            return false;
        }

        $lastVerified = strtotime($method->last_verified);
        return ($lastVerified + self::MFA_EXPIRATION_SECONDS) >= time();
    }

    public function getMethod(string $method): ?UserVerify
    {
        $userKey = $this->auth['user_key'];
        $userId = $this->auth['user_id'];

        return $userId ? $this->verifyBroker->findByMethod($userId, $method, $userKey) : null;
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

    private function extractMethodOrFail(Form $form): string
    {
        $method = $form->getValue('method');
        if (empty($method)) {
            throw new FormException($form);
        }
        return $method;
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
