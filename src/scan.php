<?php

$vendorDirectory = realpath(__DIR__.'/../../../../vendor');

require_once $vendorDirectory.'/autoload.php';

if (!file_exists($vendorDirectory) || !is_dir($vendorDirectory)) {
    die('Error locating vendor directory at: '.$vendorDirectory);
}

$apiKey = getenv('VIRUSTOTAL_API_KEY');

if (!$apiKey) {
    die('No Virus Total API key specified. Please specify one with `export VIRUSTOTAL_API_KEY=abc123`.');
}

$cacheDirectory = '~/.cache/dependency-security-checker/';

$vtFile = new VirusTotal\File($apiKey);

if (!file_exists($cacheDirectory)) {
    mkdir($cacheDirectory, 0777, true);
}

$cache = new \rapidweb\RWFileCache\RWFileCache();
$cache->changeConfig(['cacheDirectory' => $cacheDirectory, 'unixLoadUpperThreshold'  => 999]);

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

directoryScan($vendorDirectory);

function directoryScan($directory) 
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

            directoryScan($file);

        } else {

            echo $file;
            echo "\t";
            $status = fileScan($file);
            echo $status;

            if ($status=='unknown') {
                $url = fileSubmit($file);
                if ($url) {
                    echo ", ";
                    echo 'submitted';
                }
            }
            
            echo PHP_EOL;

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


