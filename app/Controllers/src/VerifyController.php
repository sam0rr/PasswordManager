<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\Mfa\AuthenticatorMfaService;
use Models\src\Services\Mfa\EmailMfaService;
use Models\src\Services\Mfa\SmsMfaService;
use Models\src\Services\VerifyService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class VerifyController extends SecureController
{
    #[Post('/verify/send')]
    public function send(): Response
    {
        $method = $this->request->getParameter('method');
        $userId = $this->getAuth()['user_id'];

        $service = $this->getService($method);
        if (!$service) {
            return $this->json("Méthode MFA invalide.");
        }

        $result = $service->sendCode($userId);

        return $this->json([
            'success' => $result !== null,
            'message' => $result ? 'Code envoyé.' : 'Impossible d’envoyer le code.',
            'qr' => $method === 'authenticator' ? $result : null
        ]);
    }

    #[Post('/verify/confirm')]
    public function confirm(): Response
    {
        $method = $this->request->getParameter('method');
        $code = $this->request->getParameter('code');
        $userId = $this->getAuth()['user_id'];

        $service = $this->getService($method);
        if (!$service) {
            return $this->json("Méthode MFA invalide.");
        }

        if (!$service->verifyCode($userId, $code)) {
            return $this->json("Code incorrect ou expiré.");
        }

        $service->getVerifyService()->markVerified($method);

        return $this->json([
            'success' => true,
            'message' => 'Vérification réussie.'
        ]);
    }

    #[Post('/verify/status')]
    public function status(): Response
    {
        $verifyService = new VerifyService($this->getAuth());

        return $this->json([
            'completed' => $verifyService->areAllMethodsVerified(),
            'pending' => $verifyService->getPendingMethods()
        ]);
    }

    private function getService(string $method): ?object
    {
        return match ($method) {
            'email' => new EmailMfaService($this->getAuth()),
            'sms' => new SmsMfaService($this->getAuth()),
            'authenticator' => new AuthenticatorMfaService($this->getAuth()),
            default => null
        };
    }
}
