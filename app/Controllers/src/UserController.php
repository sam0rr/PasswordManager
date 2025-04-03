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

        return $this->render("user/dashboard", [
            "user" => $user,
            "title" => "Tableau de bord"
        ]);
    }

    #[Post('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();

        return $this->redirect("/login");
    }
}
