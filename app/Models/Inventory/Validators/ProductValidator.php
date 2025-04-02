<?php namespace Models\Inventory\Validators;

use Models\Exceptions\FormException;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class ProductValidator
{
    public static function assert(Form $form): void
    {
        $form->field("name", [
            Rule::required(localize("errors.required"))
        ]);
        $form->field("brand", [
            Rule::required(localize("errors.required"))
        ]);
        $form->field("provider", [
            Rule::required(localize("errors.required"))
        ]);
        $form->field("price", [
            Rule::required(localize("errors.required")),
            Rule::decimal(localize("errors.money"))
        ]);
        if (!$form->verify()) {
            throw new FormException($form);
        }
    }
}
