<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\Exceptions\FormException;
use Models\src\Services\Mfa\AuthenticatorMfaService;
use Models\src\Services\Mfa\mailMfaService;
use Models\src\Services\Mfa\SmsMfaService;
use Models\src\Services\VerifyService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class VerifyController extends SecureController
{
    #[Post('/verify/activate')]
    public function activate(): Response
    {
        $form = $this->buildForm();
        $verifyService = new VerifyService($this->getAuth());

        try {
            $verify = $verifyService->handleActivation($form);

            return $this->json([
                'success' => true,
                'message' => "Méthode '{$verify->method}' activée.",
                'method' => $verify->method,
                'active' => $verify->is_active
            ]);
        } catch (FormException) {
            return $this->json([
                'success' => false,
                'errors' => $form->getErrors()
            ]);
        }
    }

    #[Post('/verify/deactivate')]
    public function deactivate(): Response
    {
        $form = $this->buildForm();
        $verifyService = new VerifyService($this->getAuth());

        try {
            $verifyService->handleDeactivation($form);

            return $this->json([
                'success' => true,
                'message' => "Méthode désactivée."
            ]);
        } catch (FormException) {
            return $this->json([
                'success' => false,
                'errors' => $form->getErrors()
            ]);
        }
    }

    #[Post('/verify/send')]
    public function send(): Response
    {
        $form = $this->buildForm();

        try {
            $service = $this->resolveMfaService($form);
            $result = $service->sendCode($this->getAuth()['user_id']);

            return $this->json([
                'success' => $result !== null,
                'message' => $result ? 'Code envoyé.' : 'Impossible d’envoyer le code.',
                'qr' => $service instanceof AuthenticatorMfaService ? $result : null
            ]);
        } catch (FormException) {
            return $this->json([
                'success' => false,
                'errors' => $form->getErrors()
            ]);
        }
    }

    #[Post('/verify/confirm')]
    public function confirm(): Response
    {
        $form = $this->buildForm();

        try {
            $service = $this->resolveMfaService($form);
            $isValid = $service->verifyCode($this->getAuth()['user_id'], $form->getValue('code'));

            if (!$isValid) {
                return $this->json([
                    'success' => false,
                    'message' => 'Code incorrect ou expiré.'
                ]);
            }

            $service->getVerifyService()->markVerified($form->getValue('method'));

            return $this->json([
                'success' => true,
                'message' => 'Vérification réussie.'
            ]);
        } catch (FormException) {
            return $this->json([
                'success' => false,
                'errors' => $form->getErrors()
            ]);
        }
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

    private function resolveMfaService($form): object
    {
        $method = $form->getValue('method');
        if (empty($method)) {
            $form->addError("method", "La méthode est requise.");
            throw new FormException($form);
        }

        return match ($method) {
            'mail' => new mailMfaService($this->getAuth()),
            'sms' => new SmsMfaService($this->getAuth()),
            'authenticator' => new AuthenticatorMfaService($this->getAuth()),
            default => throw new FormException($form->addError("method", "Méthode MFA invalide."))
        };
    }

}
