<?php

namespace Models\src\Validators;

class BaseValidator
{
    protected static function optionalIf($field, bool $isHtmx): void
    {
        if ($isHtmx) {
            $field->optional();
        }
    }
}