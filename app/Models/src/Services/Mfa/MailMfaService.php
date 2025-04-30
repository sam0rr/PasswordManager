<?php

namespace Models\src\Services\Mfa;

use Models\src\Services\Utils\BaseService;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use RuntimeException;

final class MailMfaService extends BaseService implements MfaServiceInterface
{
    private ?string $mailHost = null {
        get {
            return $this->mailHost ??= config('mailer.smtp', 'host', 'localhost');
        }
    }
    private ?int $mailPort = null {
        get {
            return $this->mailPort ??= (int)config('mailer.smtp', 'port', 1025);
        }
    }
    private ?string $mailFrom = null {
        get {
            return $this->mailFrom ??= config('mailer', 'from_address', 'noreply@kryptlok.dev');
        }
    }
    private ?string $mailFromName = null {
        get {
            return $this->mailFromName ??= config('mailer', 'from_name', 'KryptLok');
        }
    }

    public function generateSecret(): string
    {
        return (string) random_int(100000, 999999);
    }

    public function verifyCode(string $userId, string $code): bool
    {
        $method = $this->verify->getMethod('mail');

        if (!$method || !$method->is_active) {
            return false;
        }

        return $method->otp_secret === $code;
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verify->getMethod('mail');

        if (!$method || !$method->is_active) {
            return null;
        }

        $otp = $this->generateSecret();
        $email = $this->verify->getUserEmail();

        try {
            $mailer = new PHPMailer(true);
            $mailer->isSMTP();
            $mailer->Host = $this->mailHost;
            $mailer->Port = $this->mailPort;
            $mailer->SMTPAuth = false;
            $mailer->SMTPAutoTLS = false;

            $mailer->setFrom($this->mailFrom, $this->mailFromName);
            $mailer->addAddress($email);
            $mailer->Subject = 'Votre code de vérification KryptLok';
            $mailer->Body = "Voici votre code de connexion : $otp";

            $mailer->send();

            $this->verify->updateSecret($userId, 'mail', $otp);

            return $otp;
        } catch (Exception $e) {
            throw new RuntimeException("Erreur lors de l’envoi du code par email : " . $e->getMessage());
        }
    }

}
