<?php

define('ROOT_DIR', realpath(__DIR__ . '/..'));
require ROOT_DIR . '/vendor/autoload.php';

$kernel = new Models\Core\Kernel();
$response = $kernel->run();
$response->send();
