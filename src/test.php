<?php

require_once __DIR__.'/../vendor/autoload.php';

$apiKey = '';

$file = new VirusTotal\File($apiKey);

$resp = $file->getReport('69261027ca3f6f36393d8fd01df1e5dd6dbde52d4bb6fc19fa6984731936b9e0');

var_dump($resp);
