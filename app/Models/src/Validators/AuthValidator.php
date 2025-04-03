<?php

namespace Models\src\Validators;

use Models\src\Brokers\AuthBroker;
use Models\Exceptions\FormException;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class AuthValidator
{
    public static function assertRegister(Form $form, AuthBroker $broker): void
    {
        $form->field("first_name", [
            Rule::required("Le prénom est requis."),
            Rule::minLength(2, "Le prénom doit contenir au moins 2 caractères.")
        ]);

        $form->field("last_name", [
            Rule::required("Le nom est requis."),
            Rule::minLength(2, "Le nom doit contenir au moins 2 caractères.")
        ]);

        $form->field("email", [
            Rule::required("L'adresse courriel est requise."),
            Rule::email("L'adresse courriel n'est pas valide.")
        ]);

        $form->field("phone", [
            Rule::required("Le numéro de téléphone est requis."),
            Rule::phone("téléphone n'est pas valide.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe est requis."),
            Rule::minLength(8, "Le mot de passe doit contenir au moins 8 caractères.")
        ]);

        $form->field("image_url")->optional();

        if (!$form->verify()) {
            throw new FormException($form);
        }

        if ($broker->emailExists($form->getValue("email"))) {
            $form->addError("email", "Cette adresse courriel est déjà utilisée.");
            throw new FormException($form);
        }
    }

    public static function assertLogin(Form $form): void
    {
        $form->field("email", [
            Rule::required("L'adresse courriel est requise."),
            Rule::email("L'adresse courriel n'est pas valide.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe est requis.")
        ]);

        if (!$form->verify()) {
            throw new FormException($form);
        }
    }
}
