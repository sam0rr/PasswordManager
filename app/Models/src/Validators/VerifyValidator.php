<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

final class VerifyValidator extends BaseValidator
{
    public static function assertConfirm(Form $form, bool $isHtmx): void
    {
        $code = $form->field("code", [
            Rule::required("MFA Code Is Required."),
            Rule::decimal("Code Must Be Numeric."),
            Rule::length(6, "Code Must Be 6 Digits."),
        ]);
        self::optionalIf($code, $isHtmx);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

}
