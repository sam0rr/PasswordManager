<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Entities\User;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\PasswordService;
use Models\src\Services\SecurityService;
use Models\src\Services\SharingService;
use Models\src\Services\UserService;
use Zephyrus\Application\Form;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;

class DashboardController extends SecureController
{
    private UserService $userService;
    private AuthHistoryService $authHistoryService;
    private SharingService $sharingService;
    private PasswordService $passwordService;

    public function before(): ?Response
    {
        $response = parent::before();
        if (!is_null($response)) return $response;

        $auth = $this->getAuth();
        $this->userService = new UserService($auth);
        $this->authHistoryService = new AuthHistoryService($auth);
        $this->sharingService = new SharingService($auth);
        $this->passwordService = new PasswordService($auth);

        return null;
    }

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
        $this->injectDataIfNeeded($context, $section);
        $this->appendSecurityAnalysisIfNeeded($context, $section);

        return SessionHelper::getContext();
    }

    private function initializeBaseContext(User $user, string $section, string $tab): array
    {
        return [
            'title' => "Tableau de bord",
            'user' => $user,
            'auth_history' => $this->authHistoryService->getHistoryForUser(),
            'activeSection' => $section,
            'tab' => $tab
        ];
    }

    private function injectDataIfNeeded(array &$context, string $section): void
    {
        if (!SessionHelper::get("user")) {
            $context['passwordsUnlocked'] = ($section === 'passwords');
            $context['shared_credentials'] = $this->sharingService->getAllShares(new Form());
            $context['passwords'] = $this->passwordService->getAllUserPasswords(new Form());
            SessionHelper::setContext($context);
        } else {
            if ($section !== 'passwords') {
                $context['passwordsUnlocked'] = false;
            }
            SessionHelper::appendContext($context);
        }
    }

    private function appendSecurityAnalysisIfNeeded(array &$context, string $section): void
    {
        if ($section !== 'security') return;

        $passwords = SessionHelper::get('passwords', []);
        $lastMap = SessionHelper::get('security_password_fingerprint', []);
        $existing = SessionHelper::get('security_analysis', []);

        $result = SecurityService::analyzeIfChanged($passwords, $lastMap, $existing);

        SessionHelper::appendContext([
            'security_analysis' => $result['analysis'],
            'security_password_fingerprint' => $result['fingerprintMap']
        ]);

        $context['security_analysis'] = $result['analysis'];
    }

    private function getDashboardUser(): User
    {
        $user = $this->userService->getCurrentUserEntity();
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
}
