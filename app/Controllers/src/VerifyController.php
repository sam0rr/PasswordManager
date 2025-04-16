<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\Exceptions\FormException;
use Models\src\Services\Mfa\AuthenticatorMfaService;
use Models\src\Services\Mfa\MailMfaService;
use Models\src\Services\Mfa\SmsMfaService;
use Zephyrus\Network\ContentType;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

class VerifyController extends SecureController
{
    private ?MailMfaService $mailMfaService = null {
        get {
            return $this->mailMfaService ??= new MailMfaService($this->getAuth());
        }
    }
    private ?SmsMfaService $smsMfaService = null {
        get {
            return $this->smsMfaService ??= new SmsMfaService($this->getAuth());
        }
    }
    private ?AuthenticatorMfaService $authenticatorMfaService = null {
        get {
            return $this->authenticatorMfaService ??= new AuthenticatorMfaService($this->getAuth());
        }
    }

    #[Post('/verify/activate')]
    public function activate(): Response
    {
        $form = $this->buildForm();

        $this->base->verify->handleActivation($form);
        $this->setMfaContext();

        return $this->redirect('/dashboard?section=profile&tab=mfa');
    }

    #[Get('/verify/qrcode')]
    public function getQrCode(): Response
    {
        $userId = $this->getAuth()['user_id'];
        $dataUri = $this->authenticatorMfaService->sendCode($userId);

        $html = '

        <div class="qr-code-image text-center">
            <img src="' . htmlspecialchars($dataUri) . '" alt="QR Code To Scan" class="img-fluid rounded shadow" style="max-width: 250px;">
        </div>

        ';

        $response = new Response();
        $response->setContent($html);
        return $response;
    }

    #[Post('/verify/deactivate')]
    public function deactivate(): Response
    {
        $form = $this->buildForm();
        $this->base->verify->handleDeactivation($form);

        $this->setMfaContext();
        return $this->redirect('/dashboard?section=profile&tab=mfa');
    }

    #[Get('/verify-mfa')]
    public function showMfaForm(): Response
    {
        if (SessionHelper::get('mfa_validated')) {
            return $this->redirect('/dashboard');
        }

        $form = SessionHelper::getForm('mfa_confirm');
        $pendingMethods = $this->base->verify->getPendingMethods();
        $method = !empty($pendingMethods) ? reset($pendingMethods) : null;

        $this->sendMfaCodeIfNeeded($method);

        return $this->render("secure/verifyMfa", [
            'form' => $form,
            'method' => $method,
            'pendingMethods' => $pendingMethods,
            'title' => 'Vérification MFA'
        ]);
    }

    #[Post('/verify/confirm')]
    public function confirm(): Response
    {
        return $this->handleConfirmation('mfa_confirm', '/verify-mfa', 'fragments/verify/{method}Mfa');
    }

    #[Post('/verify/confirmModal')]
    public function confirmModal(): Response
    {
        return $this->handleConfirmation('mfa_confirm_modal', '/dashboard?section=profile&tab=mfa', 'fragments/verify/qrCodeModalForm');
    }

    #[Post('/verify/send')]
    public function send(): Response
    {
        $form = $this->buildForm();
        $service = $this->resolveMfaService($form);
        $service->sendCode($this->getAuth()['user_id']);

        $this->flashMessage("Le code a été envoyé avec succès.");
        SessionHelper::append(['code_sent' => true]);
        $this->setMfaContext();

        return $this->render("fragments/verify/{$form->getValue('method')}Mfa", [
            'form' => $form,
            'method' => $form->getValue('method'),
            'isHtmx' => true,
            'successMessage' => SessionHelper::consume('flash_message')
        ]);
    }

    // Helpers

    private function handleConfirmation(string $formKey, string $redirectUrl, string $fragmentTemplate): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $service = $this->resolveMfaService($form);

        $result = $this->base->verify->confirmCode($form, $service, $isHtmx);

        SessionHelper::setForm($formKey, $result['form']);

        if ($isHtmx) {
            $template = str_replace('{method}', $form->getValue('method'), $fragmentTemplate);
            return $this->render($template, [
                'form' => $result['form'],
                'method' => $form->getValue('method'),
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            return $this->redirect($redirectUrl);
        }

        SessionHelper::clearForm($formKey);
        SessionHelper::clear('code_sent');
        $this->setMfaContext();
        return $this->redirect($redirectUrl);
    }

    private function resolveMfaService($form): object
    {
        $method = $form->getValue('method');

        if (empty($method)) {
            throw new FormException($form);
        }

        return match ($method) {
            'mail' => $this->mailMfaService,
            'sms' => $this->smsMfaService,
            'authenticator' => $this->authenticatorMfaService,
            default => throw new FormException($form)
        };
    }

    private function setMfaContext(): void
    {
        SessionHelper::append([
            'mfa' => $this->base->verify->getAllActiveMethods(),
            'activeSection' => 'profile',
            'tab' => 'mfa'
        ]);
    }

    private function sendMfaCodeIfNeeded($method): void
    {
        if (SessionHelper::get('code_sent') || !$method) {
            return;
        }

        $service = match ($method->method) {
            'mail' => $this->mailMfaService,
            'sms' => $this->smsMfaService,
            default => null
        };

        if ($service) {
            $service->sendCode($this->getAuth()['user_id']);
            SessionHelper::append(['code_sent' => true]);
        }
    }

}