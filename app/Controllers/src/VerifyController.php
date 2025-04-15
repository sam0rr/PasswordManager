<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\Exceptions\FormException;
use Models\src\Services\Mfa\AuthenticatorMfaService;
use Models\src\Services\Mfa\MailMfaService;
use Models\src\Services\Mfa\SmsMfaService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class VerifyController extends SecureController
{
    #[Post('/verify/activate')]
    public function activate(): Response
    {
        $form = $this->buildForm();

        try {
            $this->getService()->verify->handleActivation($form);
            SessionHelper::clearForm('mfa_activate');
        } catch (FormException) {
            SessionHelper::setForm('mfa_activate', $form);
        }

        $this->setMfaContext();
        return $this->redirect('/dashboard?section=profile&tab=mfa');
    }

    #[Post('/verify/deactivate')]
    public function deactivate(): Response
    {
        $form = $this->buildForm();

        try {
            $this->getService()->verify->handleDeactivation($form);
            SessionHelper::clearForm('mfa_deactivate');
        } catch (FormException) {
            SessionHelper::setForm('mfa_deactivate', $form);
        }

        $this->setMfaContext();
        return $this->redirect('/dashboard?section=profile&tab=mfa');
    }

    #[Post('/verify/send')]
    public function send(): Response
    {
        $form = $this->buildForm();

        try {
            $service = $this->resolveMfaService($form);
            $service->sendCode($this->getAuth()['user_id']);
            SessionHelper::clearForm('mfa_send');
        } catch (FormException) {
            SessionHelper::setForm('mfa_send', $form);
        }

        $this->setMfaContext();
        return $this->redirect('/dashboard?section=profile&tab=mfa');
    }

    #[Post('/verify/confirm')]
    public function confirm(): Response
    {
        $form = $this->buildForm();

        try {
            $service = $this->resolveMfaService($form);
            $isValid = $service->verifyCode($this->getAuth()['user_id'], $form->getValue('code'));

            if (!$isValid) {
                $form->addError('code', 'Code incorrect ou expiré.');
                throw new FormException($form);
            }

            $service->getVerifyService()->markVerified($form->getValue('method'));
            SessionHelper::clearForm('mfa_confirm');
        } catch (FormException) {
            SessionHelper::setForm('mfa_confirm', $form);
        }

        $this->setMfaContext();
        return $this->redirect('/dashboard?section=profile&tab=mfa');
    }

    #[Post('/verify/status')]
    public function status(): Response
    {
        return $this->json([
            'completed' => $this->getService()->verify->areAllMethodsVerified(),
            'pending' => $this->getService()->verify->getPendingMethods()
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
            'mail' => new MailMfaService($this->getAuth()),
            'sms' => new SmsMfaService($this->getAuth()),
            'authenticator' => new AuthenticatorMfaService($this->getAuth()),
            default => throw new FormException($form->addError("method", "Méthode MFA invalide."))
        };
    }

    private function setMfaContext(): void
    {
        SessionHelper::appendContext([
            'mfa' => $this->getService()->verify->getAllMethods(),
            'activeSection' => 'profile',
            'tab' => 'mfa'
        ]);
    }

}
