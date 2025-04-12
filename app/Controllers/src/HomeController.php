<?php

namespace Controllers\src;

use Controllers\Controller;
use Models\src\Services\EncryptionService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;

class HomeController extends Controller
{
    #[Get('/')]
    public function home(): Response
    {
        if (EncryptionService::isAuthenticated()) {
            return $this->redirect('/dashboard');
        }
        return $this->redirect('/login');
    }

}
