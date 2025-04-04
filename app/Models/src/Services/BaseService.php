<?php

namespace Models\src\Services;

use Zephyrus\Application\Form;

abstract class BaseService
{
    protected function buildErrorResponse(Form $form): array
    {
        return [
            "status" => 400,
            "errors" => $form->getErrorMessages(),
            "form" => $form
        ];
    }
}
