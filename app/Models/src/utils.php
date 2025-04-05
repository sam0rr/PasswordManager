<?php

/**
 * Add global models functions here ...
 */

use Zephyrus\Application\Form;

function getErrorMessage(string $field, Form $form): ?string
{
    $errors = $form->getErrors();
    return $errors[$field][0] ?? null;
}

function isValidUuid(string $uuid): bool
{
    return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid);
}
