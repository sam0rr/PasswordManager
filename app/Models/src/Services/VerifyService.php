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
    private ?int $MFA_EXPIRATION_SECONDS = null {
        get {
            return $this->MFA_EXPIRATION_SECONDS ??= config('security.mfa', 'mfa_expiration_seconds', '300');
        }
    }

    private ?int $OTP_EXPIRATION_SECONDS = null {
        get {
            return $this->OTP_EXPIRATION_SECONDS ??= config('security.mfa', 'otp_expiration_seconds', '60');
        }
    }

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
            $methods = $this->verifyBroker->findAllByUser($userId, $userKey);
            return $this->sortMethodsByPriority($methods);
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
            VerifyValidator::assertConfirm($form, $isHtmx);

            $method = $form->getValue('method');
            $code = $form->getValue('code');

            $this->assertCodeValidity($code, $service, $method, $form);

            if ($isHtmx) {
                return ['form' => $form];
            }

            $this->markVerified($method);
            $this->handlePostMfaActions();

            return [
                'form' => $form,
                'method' => $method
            ];
        } catch (FormException) {
            return $this->buildErrorResponse($form);
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
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];

        if ($userId) {
            $methodEntity = $this->verifyBroker->updateLastVerified($userId, $method, $userKey);

            if ($method === 'authenticator' && !$methodEntity->is_first_verified) {
                $this->verifyBroker->markFirstVerificationDone($userId, $userKey);
            }
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

    public function getAllActiveMethods(): array
    {
        $methods = $this->getAllMethods();
        $activeMethods = array_filter($methods, fn($method) => $method->is_active);

        return $this->sortMethodsByPriority($activeMethods);
    }

    public function getPendingMethods(): array
    {
        $methods = array_filter($this->getAllMethods(), function (UserVerify $method) {
            if (!$method->is_active) {
                return false;
            }

            if ($method->method === 'authenticator' && !$method->is_first_verified) {
                return false;
            }

            return !$this->isMethodVerified($method);
        });

        return $this->sortMethodsByPriority($methods);
    }

    private function assertCodeValidity(string $code, object $service, string $method, Form $form): void
    {
        if (empty($code)) {
            return;
        }

        $isValid = $service->verifyCode($this->auth['user_id'], $code);
        if (!$isValid) {
            $form->addError('code', 'Le code est invalide.');
            throw new FormException($form);
        }
        $methodEntity = $this->getMethod($method);

        if ($this->isCodeExpired($methodEntity)) {
            $form->addError('code', 'Ce code a expiré. Veuillez en demander un nouveau.');
            throw new FormException($form);
        }
    }

    private function isCodeExpired(UserVerify $method): bool
    {
        if (empty($method->otp_created_at)) {
            return true;
        }

        $createdAt = strtotime($method->otp_created_at);
        $expiresAt = $createdAt + $this->OTP_EXPIRATION_SECONDS;

        return time() > $expiresAt;
    }

    public function isMethodVerified(UserVerify $method): bool
    {
        if (empty($method->last_verified)) {
            return false;
        }

        $lastVerified = strtotime($method->last_verified);
        $expiresAt = $lastVerified + $this->MFA_EXPIRATION_SECONDS;

        return time() <= $expiresAt;
    }

    public function getFirstUnverifiedAuthenticatorMethod(): ?UserVerify
    {
        $methods = $this->getAllActiveMethods();

        return array_find($methods, fn($method) => $method->method === 'authenticator' && !$method->is_first_verified);

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

    private function sortMethodsByPriority(array $methods): array
    {
        $priority = ['mail', 'sms', 'authenticator'];

        usort($methods, function (UserVerify $a, UserVerify $b) use ($priority) {
            return array_search($a->method, $priority) <=> array_search($b->method, $priority);
        });

        return $methods;
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
            'otp_created_at' => date('Y-m-d H:i:s'),
            'last_verified' => date('Y-m-d H:i:s', strtotime('-1 day')),
            'is_active' => true,
            'is_first_verified' => false
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
