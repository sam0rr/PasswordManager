<?php

/**
 * Add global project functions here ...
 */

use Zephyrus\Application\Form;

function getErrorMessage(string $field, Form $form): ?string
{
    $errors = $form->getErrors();
    return $errors[$field][0] ?? null;
}
