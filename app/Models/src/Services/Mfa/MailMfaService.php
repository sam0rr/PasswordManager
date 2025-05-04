<?php

namespace Models\src\Services\Mfa;

use Models\src\Services\Utils\BaseService;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Controllers\src\Utils\SessionHelper;

final class MailMfaService extends BaseService implements MfaServiceInterface
{
    private ?string $mailHost = null {
        get {
            return $this->mailHost ??= config('mailer', 'host', 'smtp.sendgrid.net');
        }
    }

    private ?int $mailPort = null {
        get {
            return $this->mailPort ??= (int) config('mailer', 'port', 587);
        }
    }

    private ?string $mailUsername = null {
        get {
            return $this->mailUsername ??= config('mailer', 'username', 'apikey');
        }
    }

    private ?string $mailPassword = null {
        get {
            return $this->mailPassword ??= config('mailer', 'password', '');
        }
    }

    private ?string $mailFrom = null {
        get {
            return $this->mailFrom ??= config('mailer', 'from_address', 'KryptLok@hotmail.com');
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
        return $method && $method->is_active && $method->otp_secret === $code;
    }

    public function sendCode(string $userId): ?string
    {
        $method = $this->verify->getMethod('mail');
        if (!$method || !$method->is_active) {
            return null;
        }

        $otp   = $this->generateSecret();
        $email = $this->verify->getUserEmail();

        try {
            $mailer = new PHPMailer(true);
            $mailer->isSMTP();
            $mailer->Host       = $this->mailHost;
            $mailer->Port       = $this->mailPort;
            $mailer->SMTPAuth   = true;
            $mailer->Username   = $this->mailUsername;
            $mailer->Password   = $this->mailPassword;
            $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;

            $mailer->setFrom($this->mailFrom, $this->mailFromName);
            $mailer->addAddress($email);
            $mailer->Subject = 'Your KryptLok Verification Code';
            $mailer->Body    = "Here Is Your Login Code: $otp";

            $mailer->send();
            $this->verify->updateSecret($userId, 'mail', $otp);

            return $otp;
        } catch (Exception) {
            SessionHelper::flash('code_send_failure', 'Unable To Send Verification Email. Please Try Again Later.', 'danger'
            );
            return null;
        }
    }
}
