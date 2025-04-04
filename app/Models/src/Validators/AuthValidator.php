<?php

namespace Models\src\Validators;

use Models\src\Brokers\AuthBroker;
use Models\Exceptions\FormException;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class AuthValidator
{
    public static function assertRegister(Form $form, AuthBroker $broker, bool $isHtmx): void
    {
        $firstNameField = $form->field("first_name", [
            Rule::required("Le prénom est requis."),
            Rule::minLength(2, "Le prénom doit contenir au moins 2 caractères.")
        ]);
        self::optionalIf($firstNameField, $isHtmx);

        $lastNameField = $form->field("last_name", [
            Rule::required("Le nom est requis."),
            Rule::minLength(2, "Le nom doit contenir au moins 2 caractères.")
        ]);
        self::optionalIf($lastNameField, $isHtmx);

        $emailField = $form->field("email", [
            Rule::required("L'adresse courriel est requise."),
            Rule::email("L'adresse courriel n'est pas valide.")
        ]);
        self::optionalIf($emailField, $isHtmx);

        $phoneField = $form->field("phone", [
            Rule::required("Le numéro de téléphone est requis."),
            Rule::phone("Le numéro de téléphone n'est pas valide.")
        ]);
        self::optionalIf($phoneField, $isHtmx);

        $passwordField = $form->field("password", [
            Rule::required("Le mot de passe est requis."),
            Rule::minLength(8, "Le mot de passe doit contenir au moins 8 caractères.")
        ]);
        self::optionalIf($passwordField, $isHtmx);

        if ($broker->emailExists($form->getValue("email"))) {
            $form->addError("email", "Cette adresse courriel est déjà utilisée.");
        }
        self::optionalIf($emailField, $isHtmx);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    public static function assertLogin(Form $form, bool $isHtmx): void
    {
        $emailField = $form->field("email", [
            Rule::required("L'adresse courriel est requise."),
            Rule::email("L'adresse courriel n'est pas valide.")
        ]);
        self::optionalIf($emailField, $isHtmx);

        $passwordField = $form->field("password", [
            Rule::required("Le mot de passe est requis."),
            Rule::minLength(8, "Le mot de passe doit contenir au moins 8 caractères.")
        ]);
        self::optionalIf($passwordField, $isHtmx);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    private static function optionalIf($field, bool $isHtmx): void
    {
        if ($isHtmx) {
            $field->optional();
        }
    }

}
