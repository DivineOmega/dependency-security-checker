<?php

use DivineOmega\CliProgressBar\ProgressBar;
use DivineOmega\DOFileCache\DOFileCache;

$vendorDirectory = realpath(__DIR__.'/../../../../vendor');
if (!file_exists($vendorDirectory) || !is_dir($vendorDirectory)) {
    $vendorDirectory = realpath(__DIR__.'/../vendor');
    if (!file_exists($vendorDirectory) || !is_dir($vendorDirectory)) {
        die('Error locating vendor directory.');
    }
}

require_once $vendorDirectory.'/autoload.php';

$apiKey = getenv('VIRUSTOTAL_API_KEY');

if (!$apiKey) {
    die('No Virus Total API key specified. Please specify one with `export VIRUSTOTAL_API_KEY=abc123`.'.PHP_EOL);
}

$cacheDirectory = $_SERVER['HOME'].'/.cache/dependency-security-checker/';

$vtFile = new VirusTotal\File($apiKey);

if (!file_exists($cacheDirectory)) {
    $directoryMade = mkdir($cacheDirectory, 0777, true);
    if (!$directoryMade) {
        die('Unable to create cache directory at: '.$cacheDirectory.PHP_EOL);
    }
}

$cache = new DOFileCache();
$cache->changeConfig(['cacheDirectory' => $cacheDirectory]);

$exclusions = [
    $vendorDirectory.'/autoload.php',
    $vendorDirectory.'/composer/autoload_namespaces.php',
    $vendorDirectory.'/composer/autoload_real.php',
    $vendorDirectory.'/composer/autoload_classmap.php',
    $vendorDirectory.'/composer/autoload_files.php',
    $vendorDirectory.'/composer/autoload_psr4.php',
    $vendorDirectory.'/composer/autoload_static.php',
    $vendorDirectory.'/composer/installed.json'
];

$filesToScan = [];

directoryScan($vendorDirectory, $filesToScan);

echo count($filesToScan)." files found.".PHP_EOL;

$progressBar = new ProgressBar();
$progressBar->setMaxProgress(count($filesToScan));

$progressBar->display();

foreach ($filesToScan as $file) {
    $fileWithoutVendorDir = str_replace($vendorDirectory, '', $file);

    $progressBar->setMessage($fileWithoutVendorDir)->display();

    $status = fileScan($file);

    if ($status=='unknown') {
        $url = fileSubmit($file);
        if ($url) {
            // Submitted file
        }
    }

    $progressBar->advance()->display();
}

$progressBar->complete();

function directoryScan($directory, &$filesToScan)
{
    $files = glob($directory.'/*');
    $dotFiles = glob($directory.'/.*');

    $files = array_merge($files, $dotFiles);

    foreach($files as $file) {

        $baseName = basename($file);

        if ($baseName=='.' || $baseName=='..') {
            continue;
        }

        if (is_dir($file)) {

            directoryScan($file, $filesToScan);

        } else {

            $filesToScan[] = $file;

        }
    }
}

function fileScan($file)
{
    global $vtFile, $cache, $exclusions;

    if (in_array($file, $exclusions)) {
        return 'skipped';
    }

    $hash = hash_file('sha256', $file);

    $response = $cache->get($hash);

    if (!$response) {

        sleep(15);
        $response = $vtFile->getReport($hash);

        $cache->set($hash, $response);

    }

    if (!isset($response['scans']) || !$response['scans']) {
        
        $status = 'unknown';
        
    } else {

        $status = 'safe';

        foreach($response['scans'] as $scan) {
            if ($scan['result']) {
                $status = 'unsafe';
                break;
            }
        }

    }

    if ($status!='safe') {
        $cache->delete($hash);
    }

    return $status;
}

function fileSubmit($file)
{
    global $vtFile, $exclusions;

    if (in_array($file, $exclusions)) {
        return 'skipped';
    }

    sleep(15);
    $response = $vtFile->scan($file);

    if (isset($response['permalink']) && $response['permalink']) {
        return $response['permalink'];
    }

    return false;
}


