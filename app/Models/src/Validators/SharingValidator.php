<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\SharingBroker;
use Models\src\Brokers\UserBroker;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class SharingValidator
{
    public static function assertShare(Form $form, UserBroker $userBroker): void
    {
        $form->field("email", [
            Rule::required("L’adresse courriel du destinataire est requise."),
            Rule::email("L’adresse courriel du destinataire est invalide.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe maître est requis.")
        ]);

        $recipient = $userBroker->findByEmail($form->getValue("email"));
        if (!$recipient) {
            $form->addError("email", "Aucun utilisateur trouvé avec cette adresse courriel.");
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
