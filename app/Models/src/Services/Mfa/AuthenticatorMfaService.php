<?php

namespace Models\src\Services\Mfa;

use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\TwoFactorAuthException;

class AuthenticatorMfaService extends BaseMfaService
{
    private TwoFactorAuth $tfa;

    public function __construct(array $auth)
    {
        parent::__construct($auth);

        try {
            $this->tfa = new TwoFactorAuth(
                new BaconQrCodeProvider(),
                'KryptLok'
            );
        } catch (TwoFactorAuthException $e) {
            throw new \RuntimeException("Error initializing 2FA: " . $e->getMessage());
        }
    }

    public function generateSecret(): string
    {
        return $this->tfa->createSecret();
    }

    public function verifyCode(string $userId, string $code): bool
    {
        $method = $this->verifyService->getMethod('authenticator');

        if (!$method || !$method->is_active) {
            return false;
        }

        return $this->tfa->verifyCode($method->otp_secret, $code);
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verifyService->getMethod('authenticator');

        if (!$method || !$method->is_active) {
            return null;
        }

        return $this->tfa->getQRCodeImageAsDataUri("KryptLok", $method->otp_secret);
    }

}
