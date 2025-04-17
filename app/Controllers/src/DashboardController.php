<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Entities\User;
use Models\src\Services\Utils\SecurityService;
use Zephyrus\Application\Form;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;

class DashboardController extends SecureController
{
    #[Get('/dashboard')]
    public function dashboard(): Response
    {
        $context = $this->buildDashboardContext();
        return $this->render("secure/dashboard", $context);
    }

    private function buildDashboardContext(): array
    {
        $user = $this->getDashboardUser();
        $section = $this->getDashboardSection();
        $tab = $this->getDashboardTab();

        $context = $this->initializeBaseContext($user, $section, $tab);
        $this->injectDataIfNeeded($context);
        $this->appendSecurityAnalysisIfNeeded($context, $section);
        $this->injectMfaConfig($context);
        $this->appendAuthenticatorWarningIfNeeded($context);

        return SessionHelper::getContext() + $context;
    }

    private function initializeBaseContext(User $user, string $section, string $tab): array
    {
        return [
            'title' => "Tableau de bord",
            'user' => $user,
            'activeSection' => $section,
            'tab' => $tab
        ];
    }

    private function injectDataIfNeeded(array &$context): void
    {
        if (!SessionHelper::get("user")) {
            $context["auth_history"] = $this->base->history->getHistoryForUser();

            $context['shared_credentials'] = $this->base->sharing->getAllShares(new Form());
            $context['passwords'] = $this->base->passwordService->getAllUserPasswords(new Form());

            $context['mfa'] = $this->base->verify->getAllActiveMethods();
            SessionHelper::setContext($context);
        } else {
            SessionHelper::append($context);
        }
    }

    private function appendSecurityAnalysisIfNeeded(array &$context, string $section): void
    {
        if ($section !== 'security') return;

        $passwords = SessionHelper::get('passwords', []);
        $lastMap = SessionHelper::get('security_password_fingerprint', []);
        $existing = SessionHelper::get('security_analysis', []);

        $result = SecurityService::analyzeIfChanged($passwords, $lastMap, $existing);

        SessionHelper::append([
            'security_analysis' => $result['analysis'],
            'security_password_fingerprint' => $result['fingerprintMap']
        ]);

        $context['security_analysis'] = $result['analysis'];
    }

    private function getDashboardUser(): User
    {
        $user = $this->base->userService->getCurrentUserEntity();
        if (!$user) {
            $this->abortNotFound("Utilisateur introuvable.");
        }
        return $user;
    }

    private function getDashboardSection(): string
    {
        return $this->request->getParameter('section') ?? 'profile';
    }

    private function getDashboardTab(): string
    {
        return $this->request->getParameter('tab') ?? 'list';
    }

    private function injectMfaConfig(array &$context): void
    {
        $context['mfa_expiration'] = config('security.mfa', 'mfa_expiration_seconds', 300);
        $context['mfa_grace_period_days'] = config('security.mfa', 'mfa_grace_period_days', 20);
    }

    private function appendAuthenticatorWarningIfNeeded(array &$context): void
    {
        $unverified = $this->base->verify->getFirstUnverifiedAuthenticatorMethod();
        if ($unverified) {
            $context['authenticator_warning_message'] = "Vous avez activé l’authentificator (TOTP). Veuillez scanner le code QR et saisir un code.";
        }
    }

}
