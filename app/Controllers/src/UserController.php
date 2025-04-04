<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\EncryptionService;
use Models\src\Brokers\AuthBroker;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

class UserController extends SecureController
{
    #[Get('/dashboard')]
    public function dashboard(): Response
    {
        $auth = $this->getAuth();
        $user = new AuthBroker()->findById($auth['user_id'], $auth['user_key']);

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
            "shared_credentials" => [] // 🟢 AJOUT ICI
        ]);

    }

    #[Get('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();

        return $this->redirect("/login");
    }
}
