<?php

namespace Models\src\Services\Mfa;

use Models\src\Services\Utils\BaseService;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\TwoFactorAuthException;
use RuntimeException as RuntimeExceptionAlias;

class AuthenticatorMfaService extends BaseService implements MfaServiceInterface
{
    private ?TwoFactorAuth $tfa = null {
        get{
            return $this->tfa ??= $this->createTfa();
        }
    }

    private function createTfa(): TwoFactorAuth
    {
        try {
            return new TwoFactorAuth(
                new BaconQrCodeProvider(),
                'KryptLok'
            );
        } catch (TwoFactorAuthException $e) {
            throw new RuntimeExceptionAlias("Error initializing 2FA: " . $e->getMessage());
        }
    }

    public function generateSecret(): string
    {
        return $this->tfa->createSecret();
    }

    public function verifyCode(string $userId, string $code): bool
    {
        $method = $this->verify->getMethod('authenticator');

        if (!$method || !$method->is_active) {
            return false;
        }

        return $this->tfa->verifyCode($method->otp_secret, $code);
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verify->getMethod('authenticator');

        if (!$method || !$method->is_active) {
            return null;
        }

        return $this->tfa->getQRCodeImageAsDataUri("KryptLok", $method->otp_secret);
    }
}
