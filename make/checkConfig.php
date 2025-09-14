<?php

$project_config_file = '../project_config.json';
$src_dir = '../src/';
$include_dir = '../include/';
$lib_dir = '../lib/';
$build_flag_file = 'build.flag';
$config = [];
$errors = [];

echo "--- Avvio della fase di analisi e configurazione ---\n";

if (!file_exists($project_config_file)) {
    $errors[] = "Errore: file di configurazione 'project_config.json' non trovato al percorso '{$project_config_file}'.";
} else {
    $config_json = file_get_contents($project_config_file);
    $config = json_decode($config_json, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        $errors[] = "Errore: file 'project_config.json' non valido. Errore: " . json_last_error_msg();
    } else {
        echo "Metadati del progetto caricati con successo.\n";
        echo "  - Nome Progetto: " . ($config['name'] ?? 'N/A') . "\n";
        echo "  - Versione: " . ($config['version'] ?? 'N/A') . "\n";
        echo "  - Autore: " . ($config['author'] ?? 'N/A') . "\n";
    }
}

function find_files_recursively($directory, $extension) {
    $files = [];
    if (!is_dir($directory)) {
        return $files;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === $extension) {
            $files[] = $file->getPathname();
        }
    }
    return $files;
}

if (!is_dir($src_dir)) {
    $errors[] = "Errore: directory sorgente '{$src_dir}' non trovata.";
} else {
    $cpp_files = find_files_recursively($src_dir, 'cpp');
    if (empty($cpp_files)) {
        $errors[] = "Errore: nessun file .cpp trovato in '{$src_dir}' (e sottocartelle).";
    }
}

if (!is_dir($include_dir)) {
    $errors[] = "Errore: directory header '{$include_dir}' non trovata.";
} else {
    $header_files = find_files_recursively($include_dir, 'h');
    if (empty($header_files)) {
        $errors[] = "Attenzione: nessun file .h trovato in '{$include_dir}' (e sottocartelle).";
    }
}

exec('g++ --version', $output, $return_code);
if ($return_code !== 0) {
    $errors[] = "Errore: Compilatore 'g++' non trovato. Assicurati che sia installato e nel PATH.";
}

if (!empty($errors)) {
    echo "--- FASE DI ANALISI FALLITA! ---\n";
    foreach ($errors as $error) {
        echo $error . "\n";
    }

    if (file_exists($build_flag_file)) {
        unlink($build_flag_file);
    }
    exit(1);
}

file_put_contents($build_flag_file, 'ok');
file_put_contents('project_config.json', json_encode($config));

echo "--- FASE DI ANALISI E CONFIGURAZIONE COMPLETATA CON SUCCESSO ---\n";
exit(0);