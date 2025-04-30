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
            Rule::required("Le code MFA est requis."),
            Rule::decimal("Le code doit être numérique."),
            Rule::length(6, "Le code doit contenir 6 chiffres."),
        ]);
        self::optionalIf($code, $isHtmx);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
