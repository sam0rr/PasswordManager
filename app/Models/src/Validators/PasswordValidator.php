<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class PasswordValidator
{
    public static function assertAdd(Form $form, PasswordBroker $broker, string $userId): void
    {
        $form->field("description", [
            Rule::required("La description est requise."),
            Rule::minLength(2, "La description doit contenir au moins 2 caractères.")
        ]);

        $form->field("note", [
            Rule::required("La note est requise."),
            Rule::minLength(2, "La note doit contenir au moins 2 caractères.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe est requis.")
        ]);

        $form->verify();

        $desc = $form->getValue("description");
        if (!empty($desc) && $broker->descriptionExistsForUser($userId, $desc)) {
            $form->addError("description", "Une description identique existe déjà.");
        }

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
