<?php

namespace Models\src\Services;

use Models\src\Brokers\UserBroker;
use Models\src\Brokers\VerifyBroker;
use Models\src\Entities\UserVerify;
use Models\src\Services\Utils\BaseService;

class VerifyService extends BaseService
{
    private VerifyBroker $verifyBroker;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->verifyBroker = new VerifyBroker();
        $this->userBroker = new UserBroker();
    }

    public function getActiveMethods(): array
    {
        return $this->verifyBroker->findActiveByUser($this->auth['user_id']);
    }

    public function getMethod(string $method): ?UserVerify
    {
        return $this->verifyBroker->findByMethod($this->auth['user_id'], $method);
    }

    public function registerMethod(string $method, string $otpSecret): UserVerify
    {
        $verify = $this->verifyBroker->createMethod([
            'user_id' => $this->auth['user_id'],
            'method' => $method,
            'otp_secret' => $otpSecret
        ]);

        $count = count($this->getActiveMethods());
        $this->userBroker->updateMfaCount($this->auth['user_id'], $count);

        return $verify;
    }

    public function markVerified(string $method): void
    {
        $this->verifyBroker->updateLastVerified($this->auth['user_id'], $method);
    }

    public function disableMethod(string $method): void
    {
        $this->verifyBroker->deactivate($this->auth['user_id'], $method);

        $count = count($this->getActiveMethods());
        $this->userBroker->updateMfaCount($this->auth['user_id'], $count);
    }

    // Helpers

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

    public function isMethodVerified(UserVerify $method): bool
    {
        if (empty($method->last_verified)) {
            return false;
        }

        $expirationDelay = 300;
        $lastVerifiedTime = strtotime($method->last_verified);

        return $lastVerifiedTime + $expirationDelay >= time();
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
        return count($this->getPendingMethods()) === 0;
    }

}
