<?php

$scripts = [
    'checkConfig.php ',
    'buildLibrary.php',
    'configRun.php'
];

$build_dir = 'build/';
$link_command_file = 'link_command.sh';
$project_config_file = 'project_config.json';
$config = json_decode(file_get_contents($project_config_file), true);
$project_name = $config['name'] ?? 'project_name';

echo "--- Avvio del processo di build completo ---\n";

foreach ($scripts as $script) {
    echo "Esecuzione di '{$script}'...\n";
    passthru("php {$script}", $return_code);
    if ($return_code !== 0) {
        echo "Errore critico: lo script '{$script}' è fallito.\n";
        exit(1);
    }
    echo "Lo script '{$script}' è stato completato con successo.\n\n";
}

echo "Avvio della compilazione e linking finali...\n";
passthru("bash {$link_command_file}", $return_code);

if ($return_code !== 0) {
    echo "Errore di compilazione/linking. Controlla il log delle librerie e i file sorgente.\n";
    exit(1);
}

echo "\n--- Build COMPLETATA con successo! ---\n";
echo "L'eseguibile si trova in '{$build_dir}{$project_name}'.\n\n";

echo "Esecuzione del programma '{$project_name}'...\n";
passthru("./{$build_dir}{$project_name}", $return_code);

echo "\nPulizia dei file temporanei...\n";
$files_to_clean = [
    'build.flag',
    'project_config.json',
    'object_list.txt',
    'build_lib.log',
    'link_command.sh'
];

foreach ($files_to_clean as $file) {
    if (file_exists($file)) {
        unlink($file);
    }
}
$objects_to_clean = glob($build_dir . '*.o');
foreach ($objects_to_clean as $object) {
    unlink($object);
}

echo "Pulizia completata.\n";
exit(0);

?>
