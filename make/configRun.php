<?php

$build_flag_file = 'build.flag';
$config_file = 'project_config.json';
$object_list_file = 'object_list.txt';
$link_command_file = 'link_command.sh';
$cpp_config_file = '../include/config.h';

if (!file_exists($build_flag_file) || !file_exists($config_file) || !file_exists($object_list_file))  {
    echo "[ERROR] - uno dei file di configurazione non e presente";
    exit(1);
}

$configJson = file_get_contents($config_file);
$config = json_decode($configJson . true);

$project_name = $config['name'] ?? 'project_name';
$version = $config['version'] ?? '1.0.0';
$author = $config['author'] ?? 'Unknown';
$defines = $config['defines'] ?? [];
$compile_options = $config['compile_options'] ?? '';
$libraries = $config['libraries'] ?? [];
$library_paths = $config['library_paths'] ?? [];
$FILE_IGNORE_EMPTY_LINES;

$object_files = file($object_list_file, $FILE_IGNORE_EMPTY_LINES | FILE_SKIP_EMPTY_LINES);
$object_files_str = implode(' ', array_map('trim', $object_files));

// 2. Genera il file 'config.h' per C++ con macro più complesse
echo "Generazione di '{$cpp_config_file}'...\n";
$cpp_config_content = <<<EOT
#pragma once
#include <string>
#include <map>

// Configurazioni del progetto generate automaticamente
const std::string PROJECT_NAME = "{$project_name}";
const std::string PROJECT_VERSION = "{$version}";
const std::string PROJECT_AUTHOR = "{$author}";

// Definizioni e opzioni globali
#define BUILD_DATE __DATE__
#define BUILD_TIME __TIME__

EOT;

foreach ($defines as $key => $value) {
    if (is_numeric($value)) {
        $cpp_config_content .= "#define {$key} {$value}\n";
    } else {
        $cpp_config_content .= "#define {$key} \"{$value}\"\n";
    }
}

$cpp_config_content .= "\n";
file_put_contents($cpp_config_file, $cpp_config_content);
echo "File di configurazione C++ '{$cpp_config_file}' generato con successo.\n";

$library_flags = array_map(function($lib) {
    return "-l{$lib}";
}, $libraries);
$library_flags_str = implode(' ', $library_flags);

$library_paths_flags = array_map(function($path) {
    return "-L{$path}";
}, $library_paths);
$library_paths_flags_str = implode(' ', $library_paths_flags);

// 4. Genera il comando di linking finale
echo "Generazione del comando di linking...\n";
$link_command_content = "#!/bin/bash\n\n";
$link_command_content .= "g++ -o {$build_dir}{$project_name} {$object_files_str} src/*.cpp {$compile_options} {$library_paths_flags_str} {$library_flags_str}\n";

file_put_contents($link_command_file, $link_command_content);
chmod($link_command_file, 0755);
echo "Comando di linking '{$link_command_file}' generato con successo.\n";
exit(0);

?>