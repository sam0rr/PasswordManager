<?php

namespace Models\src\Services\Mfa;

use Models\src\Services\VerifyService;

abstract class BaseMfaService
{
    protected VerifyService $verifyService;
    protected array $auth;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->verifyService = new VerifyService($auth);
    }

    abstract public function generateSecret(): string;
    abstract public function verifyCode(string $userId, string $code): bool;
    abstract public function sendCode(string $userId): ?string;

}
