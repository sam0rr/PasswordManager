<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\SharingService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class SharingController extends SecureController
{
    private SharingService $service;

    public function before(): ?Response
    {
        $parentResponse = parent::before();
        if (!is_null($parentResponse)) {
            return $parentResponse;
        }

        $auth = $this->getAuth();
        $this->service = new SharingService($auth);
        return null;
    }

    #[Post('/share/{id}')]
    public function sharePassword(string $id): Response
    {
        $form = $this->buildForm();
        $result = $this->service->sharePassword($form, $id);
        return $this->json($result);
    }

}
