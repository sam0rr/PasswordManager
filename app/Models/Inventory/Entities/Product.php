<?php namespace Models\Inventory\Entities;

use Models\Core\Entity;

class Product extends Entity
{
    public int $id;
    public string $name;
    public string $provider;
    public string $brand;
    public float $price;
}
