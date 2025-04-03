<?php

namespace Controllers\src;

use Controllers\SecureController;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;
use Zephyrus\Core\Session;
use Models\src\Brokers\UserBroker;

class AuthController extends SecureController
{
    #[Get('/me')]
    public function me(): Response
    {
        $auth = $this->getAuth();
        $user = new UserBroker()->findById($auth['user_id'], $auth['user_key']);

        return $user
            ? $this->json($user)
            : $this->abortNotFound("Utilisateur introuvable.");
    }


    #[Post('/logout')]
    public function logout(): Response
    {
        Session::remove('user_context');

        return $this->json([
            "message" => "Déconnexion réussie"
        ]);
    }
}
