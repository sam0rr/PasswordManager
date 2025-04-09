<?php

namespace Models\src\Validators\Utils;

class BaseValidator
{
    protected static function optionalIf($field, bool $isHtmx): void
    {
        if ($isHtmx) {
            $field->optional();
        }
    }
}