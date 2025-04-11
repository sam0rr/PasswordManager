<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\EncryptionService;
use Models\src\Services\UserService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

class UserController extends SecureController
{
    private ?UserService $userService = null;
    private ?AuthHistoryService $authHistoryService = null;

    public function before(): ?Response
    {
        $parentResponse = parent::before();
        if (!is_null($parentResponse)) {
            return $parentResponse;
        }

        $auth = $this->getAuth();
        $this->userService = new UserService($auth);
        $this->authHistoryService = new AuthHistoryService($auth);

        return null;
    }
    #[Get('/dashboard')]
    public function dashboard(): Response
    {
        $user = $this->userService->getCurrentUserEntity();
        if (!$user) {
            return $this->abortNotFound("Utilisateur introuvable.");
        }

        $params = $this->request->getParameters();
        $section = $params['section'] ?? 'profile';
        $tab = $params['tab'] ?? 'list';

        $baseContext = [
            'title' => "Tableau de bord",
            'user' => $user,
            'auth_history' => $this->getUserHistory(),
            'activeSection' => $section,
            'tab' => $tab
        ];

        if (!SessionHelper::get("user")) {
            $baseContext['passwordsUnlocked'] = ($section === 'passwords');
            SessionHelper::setContext($baseContext);
        } else {
            if ($section !== 'passwords') {
                $baseContext['passwordsUnlocked'] = false;
            }
            SessionHelper::appendContext($baseContext);
        }

        return $this->render("secure/dashboard", SessionHelper::getContext());
    }

    #[Post('/user/update')]
    public function update(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updateUser($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/profile/updateProfileForm", [
                'form' => $result['form'],
                'user' => $result['user'] ?? null,
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'form' => $result["form"],
                'user' => $result["user"] ?? null,
                'activeSection' => 'profile',
                'tab' => 'info'
            ]);
            return $this->redirect("/dashboard?section=profile&tab=info");
        }

        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Post('/update-avatar')]
    public function updateAvatar(): Response
    {
        $form = $this->buildForm();
        $files = $this->request->getFiles();
        $avatarFile = $files['avatar'] ?? null;

        $result = $this->userService->updateAvatar($form, $avatarFile);

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'form' => $result["form"],
                'user' => $this->userService->getCurrentUserEntity(),
                'activeSection' => 'profile',
                'tab' => 'info',
                'avatarError' => true
            ]);
            return $this->redirect("/dashboard?section=profile&tab=info");
        }

        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Post('/user/password')]
    public function updatePassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updatePassword($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/profile/updatePasswordForm", [
                'form' => $result["form"],
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'form' => $result["form"],
                'user' => $result["user"] ?? null,
                'activeSection' => 'profile',
                'tab' => 'password'
            ]);
            return $this->redirect("/dashboard?section=profile&tab=password");
        }

        return $this->redirect("/dashboard?section=profile&tab=password");
    }

    #[Get('/logout')]
    public function logout(): Response
    {
        SessionHelper::clearContext();
        EncryptionService::destroySession();
        return $this->redirect("/login");
    }

    private function getUserHistory(): array
    {
        return $this->authHistoryService->getHistoryForUser();
    }
}