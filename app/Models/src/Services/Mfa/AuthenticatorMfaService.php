<?php

namespace Models\src\Services\Mfa;

use Models\src\Services\Mfa\QrCodeProvider\ChillerlanQrCodeProvider;
use Models\src\Services\Utils\BaseService;
use RobThree\Auth\Algorithm;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\TwoFactorAuthException;
use Controllers\src\Utils\SessionHelper;
use RuntimeException;

final class AuthenticatorMfaService extends BaseService implements MfaServiceInterface
{
    private ?TwoFactorAuth $tfa = null {
        get {
            return $this->tfa ??= $this->createTfa();
        }
    }

    private function createTfa(): TwoFactorAuth
    {
        try {
            $qrProvider = new ChillerlanQrCodeProvider();

            return new TwoFactorAuth(
                $qrProvider,
                'KryptLok',
                6,
                30,
                Algorithm::Sha1
            );
        } catch (TwoFactorAuthException $e) {
            throw new RuntimeException("Error Initializing Two Factor Authentication: " . $e->getMessage());
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

        try {
            return $this->tfa->getQRCodeImageAsDataUri("KryptLok", $method->otp_secret);
        } catch (TwoFactorAuthException) {
            SessionHelper::flash('code_send_failure', 'Failed To Generate QR Code. Please Try Again Later.', 'danger');
            return null;
        }
    }

}
