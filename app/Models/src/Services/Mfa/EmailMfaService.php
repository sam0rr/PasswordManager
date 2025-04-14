<?php

namespace Models\src\Services\Mfa;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class EmailMfaService extends BaseMfaService
{
    private string $mailHost;
    private int $mailPort;
    private string $mailFrom;
    private string $mailFromName;

    public function __construct(array $auth)
    {
        $this->mailHost = getenv('MAIL_HOST') ?: 'localhost';
        $this->mailPort = (int)(getenv('MAIL_PORT') ?: 1025);
        $this->mailFrom = getenv('MAIL_FROM') ?: 'noreply@kryptlok.dev';
        $this->mailFromName = getenv('MAIL_FROM_NAME') ?: 'KryptLok';

        parent::__construct($auth);
    }

    public function generateSecret(): string
    {
        return (string) random_int(100000, 999999);
    }

    public function verifyCode(string $userId, string $code): bool
    {
        $method = $this->verifyService->getMethod('email');

        if (!$method || !$method->is_active) {
            return false;
        }

        return $method->otp_secret === $code;
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verifyService->getMethod('email');

        if (!$method || !$method->is_active) {
            return null;
        }

        $otp = $this->generateSecret();
        $email = $this->verifyService->getUserEmail();

        try {
            $mailer = new PHPMailer(true);
            $mailer->isSMTP();
            $mailer->Host = $this->mailHost;
            $mailer->Port = $this->mailPort;
            $mailer->SMTPAuth = false;

            $mailer->setFrom($this->mailFrom, $this->mailFromName);
            $mailer->addAddress($email);
            $mailer->Subject = 'Votre code de vérification KryptLok';
            $mailer->Body = "Voici votre code de connexion : $otp";

            $mailer->send();

            $this->verifyService->registerMethod('email', $otp);
            return $otp;
        } catch (Exception $e) {
            throw new \RuntimeException("Erreur lors de l’envoi du code par email : " . $e->getMessage());
        }
    }

}
