<?php

namespace Controllers\src;

use Controllers\Controller;
use Models\src\Services\AuthService;
use Zephyrus\Application\Form;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

class AuthController extends Controller
{
    private AuthService $userService;

    public function __construct()
    {
        $this->userService = new AuthService();
    }

    #[Get('/login')]
    public function showLoginForm(): Response
    {
        return $this->render("auth/login", [
            "form" => new Form(),
            "title" => "Connexion"
        ]);
    }

    #[Post("/login")]
    public function login(): Response
    {
        $form = $this->buildForm();
        $result = $this->userService->login($form);

        if (isset($result["errors"])) {
            return $this->render("auth/login", [
                "form" => $result["form"],
                "title" => "Connexion"
            ]);
        }

        return $this->redirect("/dashboard");
    }

    #[Get('/register')]
    public function showRegisterForm(): Response
    {
        return $this->render("auth/register", [
            "form" => new Form(),
            "title" => "Inscription"
        ]);
    }

    #[Post("/register")]
    public function register(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->userService->register($form, $isHtmx);

            if ($isHtmx) {
                return $this->render("fragments/registerForm", [
                    "form" => $result["form"]
                ]);
            }

            if (isset($result["errors"])) {
            return $this->render("auth/register", [
                "form" => $result["form"],
                "title" => "Inscription"
            ]);
        }

        return $this->redirect("/login");
    }


}
