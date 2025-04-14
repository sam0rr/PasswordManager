<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Brokers\VerifyBroker;
use Models\src\Entities\UserVerify;
use Models\src\Services\Utils\BaseService;
use Zephyrus\Application\Form;

class VerifyService extends BaseService
{
    private VerifyBroker $verifyBroker;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->verifyBroker = new VerifyBroker();
        $this->userBroker = new UserBroker();
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

    public function activateMethod(string $method): UserVerify
    {
        $existing = $this->verifyBroker->findByMethod($this->auth['user_id'], $method);

        if (!$existing) {
            $verify = $this->verifyBroker->createMethod([
                'user_id' => $this->auth['user_id'],
                'method' => $method,
                'otp_secret' => '000000',
                'last_verified' => date('Y-m-d H:i:s', strtotime('-10 minutes')),
                'is_active' => true
            ]);
        } else {
            $this->verifyBroker->activate($this->auth['user_id'], $method);
            $verify = $this->verifyBroker->findByMethod($this->auth['user_id'], $method);
        }

        $this->updateMfaCount();
        return $verify;
    }

    public function disableMethod(string $method): void
    {
        $this->verifyBroker->deactivate($this->auth['user_id'], $method);
        $this->updateMfaCount();
    }

    public function getActiveMethods(): array
    {
        return $this->verifyBroker->findActiveByUser($this->auth['user_id']);
    }

    public function getMethod(string $method): ?UserVerify
    {
        return $this->verifyBroker->findByMethod($this->auth['user_id'], $method);
    }

    public function getPendingMethods(): array
    {
        $pending = [];

        foreach ($this->getActiveMethods() as $method) {
            if (!$this->isMethodVerified($method)) {
                $pending[] = $method->method;
            }
        }

        return $pending;
    }

    public function areAllMethodsVerified(): bool
    {
        return empty($this->getPendingMethods());
    }

    // Helpers

    private function updateMfaCount(): void
    {
        $count = count($this->getActiveMethods());
        $this->userBroker->updateMfaCount($this->auth['user_id'], $count);
    }

    public function isMethodVerified(UserVerify $method): bool
    {
        if (empty($method->last_verified)) {
            return false;
        }

        $expirationDelay = 300;
        $lastVerifiedTime = strtotime($method->last_verified);

        return ($lastVerifiedTime + $expirationDelay) >= time();
    }

    public function updateSecret(string $userId, string $method, string $otp): void
    {
        $this->verifyBroker->updateSecret($userId, $method, $otp);
    }

    public function getUserEmail(): string
    {
        $user = $this->userBroker->findById($this->auth['user_id'], $this->auth['user_key']);
        return $user->email;
    }

    public function getUserPhone(): string
    {
        $user = $this->userBroker->findById($this->auth['user_id'], $this->auth['user_key']);
        return $user->phone;
    }

    private function extractMethodOrFail(Form $form): string
    {
        $method = $form->getValue('method');
        if (empty($method)) {
            $form->addError("method", "La méthode est requise.");
            throw new FormException($form);
        }
        return $method;
    }

}
