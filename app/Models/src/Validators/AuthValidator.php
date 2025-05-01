<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

final class AuthValidator extends BaseValidator
{
    public static function assertRegister(Form $form, UserBroker $broker, bool $isHtmx): void
    {
        $firstNameField = $form->field("first_name", [
            Rule::required("First Name Is Required."),
            Rule::minLength(2, "First Name Must Be At Least 2 Characters.")
        ]);
        self::optionalIf($firstNameField, $isHtmx);

        $lastNameField = $form->field("last_name", [
            Rule::required("Last Name Is Required."),
            Rule::minLength(2, "Last Name Must Be At Least 2 Characters.")
        ]);
        self::optionalIf($lastNameField, $isHtmx);

        $emailField = $form->field("email", [
            Rule::required("Email Address Is Required."),
            Rule::email("Email Address Is Invalid.")
        ]);
        self::optionalIf($emailField, $isHtmx);

        $phoneField = $form->field("phone", [
            Rule::required("Phone Number Is Required."),
            Rule::phone("Phone Number Is Invalid.")
        ]);
        self::optionalIf($phoneField, $isHtmx);

        $passwordField = $form->field("password", [
            Rule::required("Password Is Required."),
            Rule::minLength(8, "Password Must Be At Least 8 Characters.")
        ]);
        self::optionalIf($passwordField, $isHtmx);

        if ($broker->emailExists($form->getValue("email"))) {
            $form->addError("email", "This Email Address Is Already In Use.");
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
            Rule::required("Email Address Is Required."),
            Rule::email("Email Address Is Invalid.")
        ]);
        self::optionalIf($emailField, $isHtmx);

        $passwordField = $form->field("password", [
            Rule::required("Password Is Required."),
            Rule::minLength(8, "Password Must Be At Least 8 Characters.")
        ]);
        self::optionalIf($passwordField, $isHtmx);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

}
