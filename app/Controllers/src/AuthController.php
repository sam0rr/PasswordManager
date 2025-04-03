<?php

namespace Controllers\src;

use Controllers\Controller;
use Models\src\Services\AuthService;
use Zephyrus\Network\ContentType;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class AuthController extends Controller
{
    private AuthService $userService;

    public function __construct()
    {
        $this->userService = new AuthService();
    }

    #[Post("/register")]
    public function register(): Response
    {
        $form = $this->buildForm();
        $result = $this->userService->register($form);

        if (isset($result["errors"])) {
            return $this->abortBadRequest(json_encode(["errors" => $result["errors"]]), ContentType::JSON);
        }

        return $this->json($result);
    }

    #[Post("/login")]
    public function login(): Response
    {
        $form = $this->buildForm();
        $result = $this->userService->login($form);

        if (isset($result["errors"])) {
            return $this->abortUnauthorized(json_encode(["errors" => $result["errors"]]), ContentType::JSON);
        }

        return $this->json($result);
    }

}
