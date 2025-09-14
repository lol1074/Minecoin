<?php

$build_flag_file = 'build.flag';
$lib_dir = '../lib/';
$build_dir = '../build/';
$object_list_file = 'object_list.txt';
$log_file = 'build_lib.log';

if (!file_exists($build_flag_file)) {
      echo "[ERROR] - La fase di configurazione non è stata completata o è fallita.\n";
      exit(1);
}

if (!is_dir($build_dir)) {
    mkdir($build_dir, 0777, true);
}


$libFile = glob($lib_dir . '*.cpp');
$objectFile = [];

if (empty($libFile)) {
    echo "[ERROR] - nessun file trovato in lib/.\n";
    file_put_contents($object_list_file, '');
    exit(1);
}

$log_handle = fopen($log_file, 'w');

foreach ($libFile as $file) {
    $objectFile = $build_dir . basename($file, '.cpp') . '.o';
    $command = "g++ -c -o {$object_file} {$file}";

    echo "Compilazione di " . basename($file) . "...\n";
    fwrite($log_handle, "Comando: {$command}\n");

    exec($command, $output, $returnCode);

    if($returnCode !== 0) {
        echo "Errore durante la compilazione di " . basename($file) . "\n";
        fwrite($log_handle, "Errore: " . implode("\n", $output) . "\n");
        fclose($log_handle);
        exit(1);
    }

    $object_file[] = $object_file;
}

fclose($log_handle);
echo "[SUCESS] - Compilazione delle librerie completata con successo.\n";
file_put_contents($object_list_file, implode("\n", $object_files));

exit(0);
?>
