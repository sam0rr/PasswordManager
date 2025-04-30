<?php

namespace Controllers\src;

use Controllers\Controller;
use Models\src\Services\Utils\Session\SessionContextService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;

final class HomeController extends Controller
{
    #[Get('/')]
    public function home(): Response
    {
        if (SessionContextService::isAuthenticated()) {
            return $this->redirect('/dashboard');
        }
        return $this->redirect('/login');
    }

}
