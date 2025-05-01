<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

final class SharingValidator extends BaseValidator
{
    public static function assertShare(Form $form, UserBroker $userBroker, string $ownerId, bool $isHtmx): void
    {
        $emailField = $form->field("email", [
            Rule::required("Recipient Email Address Is Required."),
            Rule::email("Recipient Email Address Is Invalid.")
        ]);
        self::optionalIf($emailField, $isHtmx);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }

        $recipientEmail = $form->getValue("email");
        if (!empty($recipientEmail)) {
            $recipient = $userBroker->findByEmail($recipientEmail);
            $currentUser = $userBroker->findById($ownerId);

            if (!$recipient) {
                $form->addError("email", "No User Found With This Email Address.");
            } elseif ($recipient->id === $currentUser->id) {
                $form->addError("email", "You Cannot Share A Password With Yourself.");
            }

            if ($form->hasError()) {
                throw new FormException($form);
            }
        }
    }

}
