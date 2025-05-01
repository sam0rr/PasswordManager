<?php

namespace Models\src\Services\Mfa;

use Exception;
use Models\src\Services\Utils\BaseService;
use RuntimeException as RuntimeExceptionAlias;
use Twilio\Rest\Client;

final class SmsMfaService extends BaseService implements MfaServiceInterface
{
    private ?Client $twilioClient = null {
        get {
            return $this->twilioClient ??= $this->createTwilioClient();
        }
    }

    private ?string $fromPhone = null {
        get {
            return $this->fromPhone ??= config('twilio', 'phone_from', '000000000');
        }
    }

    private function createTwilioClient(): Client
    {
        try {
            $accountSid = config('twilio', 'account_sid');
            $authToken = config('twilio', 'auth_token');

            if (!$accountSid || !$authToken) {
                throw new RuntimeExceptionAlias("Twilio credentials are missing.");
            }

            return new Client($accountSid, $authToken);
        }
        catch (Exception $e) {
            throw new RuntimeExceptionAlias("Error initializing 2FA: " . $e->getMessage());
        }
    }

    public function generateSecret(): string
    {
        return (string) random_int(100000, 999999);
    }

    public function verifyCode(string $userId, string $code): bool
    {
        $method = $this->verify->getMethod('sms');

        if (!$method || !$method->is_active) {
            return false;
        }

        return $method->otp_secret === $code;
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verify->getMethod('sms');

        if (!$method || !$method->is_active) {
            return null;
        }

        $otp = $this->generateSecret();
        $phone = $this->verify->getUserPhone();

        try {
            $this->twilioClient->messages->create(
                $phone,
                [
                    'from' => $this->fromPhone,
                    'body' => "Votre code de sécurité KryptLok est : $otp"
                ]
            );

            $this->verify->updateSecret($userId, 'sms', $otp);
            return $otp;
        } catch (Exception $e) {
            throw new RuntimeExceptionAlias("Erreur lors de l'envoi du code par SMS : " . $e->getMessage());
        }
    }

}