<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\UserService;
use Models\src\Services\EncryptionService;
use Zephyrus\Application\Form;
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

        $activeSection = $this->request->getParameter('section') ?? 'profile';
        $tab = $this->request->getParameter('tab') ?? 'info';

        return $this->render("secure/dashboard", [
            "user" => $user,
            "title" => "Tableau de bord",
            "stats" => [],
            "passwords" => [],
            "shared_passwords" => [],
            "auth_history" => $this->getUserHistory(),
            "shared_credentials" => [],
            "passwordsUnlocked" => false,
            "activeSection" => $activeSection,
            "tab" => $tab,
            "form" => new Form()
        ]);
    }

    #[Post('/update')]
    public function update(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updateUser($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/updateProfileForm", [
                "form" => $result["form"],
                "user" => $result["user"] ?? null,
                "isHtmx" => true
            ]);
        }

        if (isset($result["errors"])) {
            return $this->render("secure/dashboard", [
                "form" => $result["form"],
                "user" => $result["user"] ?? null,
                "activeSection" => 'profile',
                "tab" => 'info',
                "isHtmx" => false
            ]);
        }

        return $this->redirect("/dashboard?section=profile");
    }

    #[Post('/upload-avatar')]
    public function uploadAvatar(): Response
    {
        $result = $this->userService->uploadAvatar($this->request->getFiles());

        if (isset($result['error'])) {
            return $this->json(['error' => $result['error']]);
        }

        return $this->render("fragments/avatarPreview", [
            'imageUrl' => $result['imageUrl']
        ]);
    }

    #[Post('/password')]
    public function updatePassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updatePassword($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/updatePasswordForm", [
                "form" => $result["form"],
                "isHtmx" => true
            ]);
        }

        if (isset($result["errors"])) {
            return $this->render("secure/dashboard", [
                "form" => $result["form"],
                "user" => $result["user"] ?? null,
                "activeSection" => 'profile',
                "tab" => 'password',
                "isHtmx" => false
            ]);
        }

        return $this->redirect("/dashboard?section=profile&tab=password");
    }

    #[Get('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();
        return $this->redirect("/login");
    }

    private function getUserHistory(): array
    {
        return $this->authHistoryService->getHistoryForUser();
    }
}