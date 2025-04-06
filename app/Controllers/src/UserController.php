<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\UserService;
use Models\src\Services\EncryptionService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Put;

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

        return $this->render("secure/dashboard", [
            "user" => $user,
            "title" => "Tableau de bord",
            "stats" => [],
            "passwords" => [],
            "shared_passwords" => [],
            "auth_history" => [],
            "shared_credentials" => []
        ]);
    }

    #[Get('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();

        return $this->redirect("/login");
    }

    #[Get('/me')]
    public function me(): Response
    {
        $user = $this->userService->getCurrentUser();

        if (!$user) {
            return $this->abortUnauthorized("Utilisateur introuvable.");
        }

        return $this->json($user);
    }

    #[Put('/update')]
    public function update(): Response
    {
        $form = $this->buildForm();

        $result = $this->userService->updateUser($form);

        return $this->json($result);
    }

    #[Put('/password')]
    public function updatePassword(): Response
    {
        $form = $this->buildForm();

        $result = $this->userService->updatePassword($form);

        return $this->json($result);
    }

    #[Get('/history')]
    public function history(): Response
    {
        $history = $this->authHistoryService->getHistoryForUser();

        return $this->json([
            "status" => 200,
            "history" => $history
        ]);
    }



}
