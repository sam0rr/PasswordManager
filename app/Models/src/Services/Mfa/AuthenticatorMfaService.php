<?php

namespace Models\src\Services\Mfa;

use Models\src\Services\Utils\BaseService;
use RobThree\Auth\Algorithm;
use RobThree\Auth\Providers\Qr\EndroidQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\TwoFactorAuthException;

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
            $qrProvider = new EndroidQrCodeProvider(
                'ffffff',
                '4a90e2',
                0,
                'H',
            );

            return new TwoFactorAuth(
                $qrProvider,
                'KryptLok',
                6,
                30,
                Algorithm::Sha1
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
