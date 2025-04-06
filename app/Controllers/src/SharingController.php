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

        $this->service = new SharingService();
        return null;
    }

    #[Post('/share')]
    public function sharePassword(): Response
    {
        $form = $this->buildForm();
        $result = $this->service->sharePassword($form);
        return $this->json($result);
    }
}
