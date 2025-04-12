<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Entities\User;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\EncryptionService;
use Models\src\Services\PasswordService;
use Models\src\Services\SecurityService;
use Models\src\Services\SharingService;
use Models\src\Services\UserService;
use Zephyrus\Application\Form;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

class UserController extends SecureController
{
    private ?UserService $userService = null;
    private ?AuthHistoryService $authHistoryService = null;
    private ?SharingService $sharingService = null;
    private ?PasswordService $passwordService = null;

    public function before(): ?Response
    {
        $parentResponse = parent::before();
        if (!is_null($parentResponse)) {
            return $parentResponse;
        }

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

    #[Post('/user/update')]
    public function update(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updateUser($form, $isHtmx);

        SessionHelper::setForm('user_update', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/profile/updateProfileForm", [
                'form' => $result['form'],
                'user' => $result['user'] ?? null,
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'user' => $result["user"] ?? null,
                'activeSection' => 'profile',
                'tab' => 'info'
            ]);
            return $this->redirect("/dashboard?section=profile&tab=info");
        }

        SessionHelper::clearForm('user_update');
        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Post('/update-avatar')]
    public function updateAvatar(): Response
    {
        $form = $this->buildForm();
        $files = $this->request->getFiles();
        $avatarFile = $files['avatar'] ?? null;

        $result = $this->userService->updateAvatar($form, $avatarFile);

        SessionHelper::setForm('user_avatar', $result['form']);

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'user' => $this->userService->getCurrentUserEntity(),
                'activeSection' => 'profile',
                'tab' => 'info',
                'avatarError' => true
            ]);
            return $this->redirect("/dashboard?section=profile&tab=info");
        }

        SessionHelper::clearForm('user_avatar');
        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Post('/user/password')]
    public function updatePassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updatePassword($form, $isHtmx);

        SessionHelper::setForm('user_password', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/profile/updatePasswordForm", [
                'form' => $result["form"],
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'user' => $result["user"] ?? null,
                'activeSection' => 'profile',
                'tab' => 'password'
            ]);
            return $this->redirect("/dashboard?section=profile&tab=password");
        }

        SessionHelper::clearForm('user_password');
        return $this->redirect("/dashboard?section=profile&tab=password");
    }

    #[Get('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();
        return $this->redirect("/login");
    }

    // Helpers

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
            'auth_history' => $this->getDashboardHistory(),
            'activeSection' => $section,
            'tab' => $tab
        ];
    }

    private function injectDataIfNeeded(array &$context, string $section): void
    {
        if (!SessionHelper::get("user")) {
            $context['passwordsUnlocked'] = ($section === 'passwords');
            $context['shared_credentials'] = $this->getInitialSharesIfNeeded();
            $context['passwords'] = $this->getInitialPasswordsIfNeeded();
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
        if ($section !== 'security') {
            return;
        }

        $passwords = SessionHelper::get('passwords', []);
        $currentFingerprint = $this->generatePasswordFingerprint($passwords);
        $lastFingerprint = SessionHelper::get('security_password_fingerprint', []);

        if ($currentFingerprint !== $lastFingerprint) {
            $analysis = SecurityService::analyzeSecurity($passwords);
            SessionHelper::appendContext([
                'security_analysis' => $analysis,
                'security_password_fingerprint' => $currentFingerprint
            ]);
        }

        $context['security_analysis'] = SessionHelper::get('security_analysis', []);
    }

    private function generatePasswordFingerprint(array $passwords): array
    {
        return array_map(fn($pwd) =>
        md5($pwd->description . '::' . ($pwd->note ?? '') . '::' . $pwd->password),
            $passwords
        );
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

    private function getDashboardHistory(): array
    {
        return $this->authHistoryService->getHistoryForUser();
    }

    private function getInitialSharesIfNeeded(): array
    {
        return $this->sharingService->getAllShares(new Form());
    }

    private function getInitialPasswordsIfNeeded(): array
    {
        return $this->passwordService->getAllUserPasswords(new Form());
    }

}
