<?php

namespace Controllers\src;

use Controllers\Controller;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\AuthService;
use Zephyrus\Application\Form;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

final class AuthController extends Controller
{
    private ?AuthService $authService = null {
        get {
            return $this->authService ??= new AuthService();
        }
    }

    #[Get('/login')]
    public function showLoginForm(): Response
    {
        $form = new Form();
        if ($this->request->getParameter('error') === 'too_many_attempts') {
            $form->addError('global', "Too Many Failed Attempts Recently. Please Try Again Later.");
        }

        return $this->render("auth/login", [
            "form" => $form,
            "title" => "Login"
        ]);
    }

    #[Post("/login")]
    public function login(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->authService->login($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/auth/loginForm", [
                "form" => $result["form"],
                "isHtmx" => true
            ]);
        }

        if (isset($result["errors"])) {
            return $this->render("auth/login", [
                "form" => $result["form"],
                "title" => "Login",
                "isHtmx" => false
            ]);
        }

        if (!SessionHelper::get('mfa_validated')) {
            return $this->redirect("/verify-mfa");
        }

        return $this->redirect("/dashboard");
    }

    #[Get('/register')]
    public function showRegisterForm(): Response
    {
        return $this->render("auth/register", [
            "form" => new Form(),
            "title" => "Register"
        ]);
    }

    #[Post("/register")]
    public function register(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->authService->register($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/auth/registerForm", [
                "form" => $result["form"],
            ]);
        }

        if (isset($result["errors"])) {
            return $this->render("auth/register", [
                "form" => $result["form"],
                "title" => "Register"
            ]);
        }

        return $this->redirect("/login");
    }
}
