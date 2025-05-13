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
        if ($this->request->getParameter('error') === 'too_many_attempts') {
            SessionHelper::flash('login_error', "Too Many Failed Attempts Recently. Please Try Again Later.", 'danger');
        }

        return $this->render("auth/login", [
            "form" => SessionHelper::getForm('auth_login') ?? new Form(),
            "title" => "Login"
        ]);
    }

    #[Get('/register')]
    public function showRegisterForm(): Response
    {
        $form = SessionHelper::getForm('auth_register') ?? new Form();

        return $this->render("auth/register", [
            "form" => $form,
            "title" => "Register"
        ]);
    }

    #[Post("/login")]
    public function login(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->authService->login($form, $isHtmx);

        SessionHelper::setForm('auth_login', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/auth/loginForm", [
                "form" => $result["form"]
            ]);
        }

        if (isset($result["errors"])) {
            return $this->redirect("/login");
        }

        SessionHelper::clearForm('auth_login');

        if (!SessionHelper::get('mfa_validated')) {
            return $this->redirect("/verify-mfa");
        }

        return $this->redirect("/dashboard");
    }

    #[Post("/register")]
    public function register(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->authService->register($form, $isHtmx);

        SessionHelper::setForm('auth_register', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/auth/registerForm", [
                "form" => $result["form"],
            ]);
        }

        if (isset($result["errors"])) {
            return $this->redirect("/register");
        }

        SessionHelper::clearForm('auth_register');
        return $this->redirect("/login");
    }

}
