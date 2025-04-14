<?php

namespace Models\src\Services\Mfa;

Interface MfaServiceInterface
{
    public function generateSecret(): string;
    public function verifyCode(string $userId, string $code): bool;
    public function sendCode(string $userId): ?string;

}
