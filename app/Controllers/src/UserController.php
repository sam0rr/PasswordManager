<?php

namespace Controllers\src;

use Controllers\Controller;
use Models\src\Services\UserService;
use Zephyrus\Network\ContentType;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;


class UserController extends Controller
{
    private UserService $userService;

    public function __construct()
    {
        $this->userService = new UserService();
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
