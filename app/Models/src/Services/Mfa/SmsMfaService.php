<?php

namespace Models\src\Services\Mfa;

use Twilio\Rest\Client;

class SmsMfaService extends BaseMfaService
{
    private Client $twilioClient;
    private string $accountSid;
    private string $fromPhone;
    private string $authToken;

    public function __construct(array $auth)
    {
        $this->accountSid = getenv('TWILIO_ACCOUNT_SID');
        $this->authToken = getenv('TWILIO_AUTH_TOKEN');
        $this->fromPhone = getenv('TWILIO_PHONE_FROM');

        parent::__construct($auth);

        if (!$this->accountSid || !$this->authToken) {
            throw new \RuntimeException("Twilio credentials are missing.");
        }

        $this->twilioClient = new Client($this->accountSid, $this->authToken);
    }

    public function generateSecret(): string
    {
        return (string) random_int(100000, 999999);
    }

    public function verifyCode(string $userId, string $code): bool
    {
        $method = $this->verifyService->getMethod('sms');

        if (!$method || !$method->is_active) {
            return false;
        }

        return $method->otp_secret === $code;
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verifyService->getMethod('sms');

        if (!$method || !$method->is_active) {
            return null;
        }

        $otp = $this->generateSecret();
        $phone = $this->verifyService->getUserPhone();

        try {
            $this->twilioClient->messages->create(
                $phone,
                [
                    'from' => $this->fromPhone,
                    'body' => "Votre code de sécurité KryptLok est : $otp"
                ]
            );

            $this->verifyService->updateSecret($userId, 'sms', $otp);

            return $otp;
        } catch (\Exception $e) {
            throw new \RuntimeException("Erreur lors de l’envoi du code par SMS : " . $e->getMessage());
        }
    }
}
