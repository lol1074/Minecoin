// Test completo per BootstrapManager
#include "bootstrap_manager.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

// Callback per progresso
void OnProgress(BootstrapCore::BootstrapState state, float progress, const std::string& message) {
    std::cout << "[PROGRESS " << std::fixed << std::setprecision(1) << progress << "%] ";
    std::cout << "State: " << static_cast<int>(state) << " - " << message << std::endl;
}

// Callback per errori
void OnError(int errorCode, const std::string& message) {
    std::cout << "\033[1;31m[ERROR " << errorCode << "]\033[0m " << message << std::endl;
}

// Callback per security alerts
bool OnSecurityAlert(const std::string& threat, int severity) {
    std::cout << "\033[1;33m[SECURITY ALERT - Level " << severity << "]\033[0m " << threat << std::endl;
    
    // Ritorna false per permettere al bootstrap di continuare anche con alert
    // Ritorna true per bloccare l'esecuzione
    return false; // Continua
}

// Callback per validazione
bool OnValidation(const std::vector<uint8_t>& data) {
    std::cout << "[VALIDATION] Validating " << data.size() << " bytes" << std::endl;
    return true; // Accetta sempre per test
}

void PrintSeparator(const std::string& title = "") {
    std::cout << "\n";
    std::cout << "================================================================" << std::endl;
    if (!title.empty()) {
        std::cout << "  " << title << std::endl;
        std::cout << "================================================================" << std::endl;
    }
}

void PrintSystemInfo(const BootstrapCore::SystemFingerprint& fingerprint) {
    PrintSeparator("SYSTEM FINGERPRINT");
    std::cout << "Hardware ID:     " << fingerprint.hardwareId << std::endl;
    std::cout << "CPU Signature:   " << fingerprint.cpuSignature << std::endl;
    std::cout << "BIOS Version:    " << fingerprint.biosVersion << std::endl;
    std::cout << "OS Version:      " << fingerprint.osVersion << std::endl;
    std::cout << "MAC Address:     " << fingerprint.macAddress << std::endl;
    std::cout << "Disk Serial:     " << fingerprint.diskSerial << std::endl;
    std::cout << "Memory Size:     " << (fingerprint.memorySize / (1024*1024)) << " MB" << std::endl;
    std::cout << "Processor Count: " << fingerprint.processorCount << std::endl;
    std::cout << "Software Count:  " << fingerprint.installedSoftware.size() << std::endl;
}

void PrintProcessMetrics(const BootstrapCore::ProcessMetrics& metrics) {
    PrintSeparator("PROCESS METRICS");
    std::cout << "Memory Usage:       " << (metrics.memoryUsage / (1024*1024)) << " MB" << std::endl;
    std::cout << "CPU Usage:          " << std::fixed << std::setprecision(2) << (metrics.cpuUsage * 100) << "%" << std::endl;
    std::cout << "Thread Count:       " << metrics.threadCount << std::endl;
    std::cout << "Handle Count:       " << metrics.handleCount << std::endl;
    std::cout << "Loaded Modules:     " << metrics.loadedModules.size() << std::endl;
    std::cout << "Debugger Detected:  " << (metrics.debuggerDetected ? "YES" : "NO") << std::endl;
    std::cout << "Injection Detected: " << (metrics.injectionDetected ? "YES" : "NO") << std::endl;
    std::cout << "Tampering Detected: " << (metrics.tamperingDetected ? "YES" : "NO") << std::endl;
}

void PrintPerformanceMetrics(const std::map<std::string, double>& metrics) {
    PrintSeparator("PERFORMANCE METRICS");
    for (const auto& pair : metrics) {
        std::cout << std::setw(25) << std::left << pair.first << ": " 
                  << std::fixed << std::setprecision(2) << pair.second << std::endl;
    }
}

void PrintInitializationLog(const std::vector<std::string>& log) {
    PrintSeparator("INITIALIZATION LOG");
    size_t startIdx = log.size() > 20 ? log.size() - 20 : 0;
    std::cout << "Showing last " << (log.size() - startIdx) << " of " << log.size() << " entries:" << std::endl;
    for (size_t i = startIdx; i < log.size(); ++i) {
        std::cout << log[i] << std::endl;
    }
}

int main(int argc, char* argv[]) {
    PrintSeparator("BOOTSTRAP MANAGER - FULL TEST");
    
    std::cout << "\nBootstrap Version: " << BootstrapUtils::GetBootstrapVersion() << std::endl;
    std::cout << "Build Timestamp:   " << BootstrapUtils::GetBuildTimestamp() << std::endl;
    std::cout << "Debug Build:       " << (BootstrapUtils::IsDebugBuild() ? "YES" : "NO") << std::endl;
    std::cout << "Production:        " << (BootstrapUtils::IsProductionEnvironment() ? "YES" : "NO") << std::endl;
    
    // Crea configurazione personalizzata
    BootstrapCore::BootstrapConfiguration config;
    config.securityLevel = BootstrapCore::SecurityLevel::ENHANCED;
    config.enableAntiDebug = true;
    config.enableCodeObfuscation = true;
    config.enableMemoryProtection = true;
    config.enableNetworkValidation = false; // Disabilitato per test locale
    config.enableHardwareFingerprinting = true;
    config.enableSelfDestruct = false; // Disabilitato per test!
    config.maxInitializationTime = 60000; // 60 secondi
    config.heartbeatInterval = 2000; // 2 secondi
    config.encryptionKey = "test_encryption_key_12345678";
    
    PrintSeparator("CONFIGURATION");
    std::cout << "Security Level:              " << static_cast<int>(config.securityLevel) << std::endl;
    std::cout << "Anti-Debug:                  " << (config.enableAntiDebug ? "ON" : "OFF") << std::endl;
    std::cout << "Code Obfuscation:            " << (config.enableCodeObfuscation ? "ON" : "OFF") << std::endl;
    std::cout << "Memory Protection:           " << (config.enableMemoryProtection ? "ON" : "OFF") << std::endl;
    std::cout << "Network Validation:          " << (config.enableNetworkValidation ? "ON" : "OFF") << std::endl;
    std::cout << "Hardware Fingerprinting:     " << (config.enableHardwareFingerprinting ? "ON" : "OFF") << std::endl;
    std::cout << "Self-Destruct:               " << (config.enableSelfDestruct ? "ON" : "OFF") << std::endl;
    std::cout << "Max Init Time:               " << config.maxInitializationTime << " ms" << std::endl;
    std::cout << "Heartbeat Interval:          " << config.heartbeatInterval << " ms" << std::endl;
    
    try {
        PrintSeparator("CREATING BOOTSTRAP MANAGER");
        
        // Crea bootstrap manager
        BootstrapManager manager(config);
        
        std::cout << "Bootstrap manager created successfully" << std::endl;
        
        // Imposta callbacks
        manager.SetProgressCallback(OnProgress);
        manager.SetErrorCallback(OnError);
        manager.SetSecurityCallback(OnSecurityAlert);
        manager.SetValidationCallback(OnValidation);
        
        std::cout << "Callbacks registered" << std::endl;
        
        // Inizializzazione
        PrintSeparator("INITIALIZATION PHASE");
        
        auto initStart = std::chrono::steady_clock::now();
        bool initSuccess = manager.Initialize();
        auto initEnd = std::chrono::steady_clock::now();
        
        auto initDuration = std::chrono::duration_cast<std::chrono::milliseconds>(initEnd - initStart);
        
        if (initSuccess) {
            std::cout << "\n\033[1;32m[SUCCESS]\033[0m Bootstrap initialized in " 
                      << initDuration.count() << " ms" << std::endl;
        } else {
            std::cout << "\n\033[1;31m[FAILED]\033[0m Bootstrap initialization failed after " 
                      << initDuration.count() << " ms" << std::endl;
            return 1;
        }
        
        // Verifica stato
        std::cout << "\nCurrent State: " << static_cast<int>(manager.GetCurrentState()) << std::endl;
        std::cout << "Progress: " << manager.GetInitializationProgress() << "%" << std::endl;
        
        // Stampa informazioni di sistema
        PrintSystemInfo(manager.GetSystemFingerprint());
        
        // Avvio del sistema
        PrintSeparator("STARTING BOOTSTRAP SYSTEM");
        
        bool startSuccess = manager.Start();
        if (startSuccess) {
            std::cout << "\033[1;32m[SUCCESS]\033[0m Bootstrap system started" << std::endl;
        } else {
            std::cout << "\033[1;31m[FAILED]\033[0m Bootstrap system start failed" << std::endl;
            return 1;
        }
        
        // Attendi un po' per permettere ai thread di lavorare
        std::cout << "\nWaiting 5 seconds for monitoring threads..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        // Verifica health
        PrintSeparator("HEALTH CHECK");
        
        bool isRunning = manager.IsRunning();
        bool isHealthy = manager.IsHealthy();
        
        std::cout << "Is Running: " << (isRunning ? "\033[1;32mYES\033[0m" : "\033[1;31mNO\033[0m") << std::endl;
        std::cout << "Is Healthy: " << (isHealthy ? "\033[1;32mYES\033[0m" : "\033[1;31mNO\033[0m") << std::endl;
        
        // Metriche processo
        PrintProcessMetrics(manager.GetProcessMetrics());
        
        // Metriche performance
        PrintPerformanceMetrics(manager.GetPerformanceMetrics());
        
        // Test validazioni sicurezza
        PrintSeparator("SECURITY VALIDATION");
        
        bool securityValid = manager.PerformSecurityValidation();
        std::cout << "Security Validation: " << (securityValid ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        bool integrityValid = manager.PerformIntegrityCheck();
        std::cout << "Integrity Check: " << (integrityValid ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        bool envValid = manager.ValidateSystemEnvironment();
        std::cout << "Environment Validation: " << (envValid ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        bool hostileDetected = manager.DetectHostileEnvironment();
        std::cout << "Hostile Environment: " << (hostileDetected ? "\033[1;31mDETECTED\033[0m" : "\033[1;32mNOT DETECTED\033[0m") << std::endl;
        
        // Test crittografia
        PrintSeparator("ENCRYPTION TEST");
        
        bool encryptSuccess = manager.EncryptSensitiveData();
        std::cout << "Encrypt Sensitive Data: " << (encryptSuccess ? "\033[1;32mSUCCESS\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        std::vector<uint8_t> sessionKey = manager.GenerateSessionKey();
        std::cout << "Generated Session Key: " << sessionKey.size() << " bytes" << std::endl;
        std::cout << "Key (hex): " << BootstrapUtils::BytesToHexString(sessionKey).substr(0, 32) << "..." << std::endl;
        
        bool cryptoValid = manager.ValidateEncryption();
        std::cout << "Encryption Validation: " << (cryptoValid ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        // Test stealth mode
        PrintSeparator("STEALTH MODE TEST");
        
        bool stealthEnabled = manager.EnableStealthMode();
        std::cout << "Enable Stealth Mode: " << (stealthEnabled ? "\033[1;32mSUCCESS\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        bool stealthDisabled = manager.DisableStealthMode();
        std::cout << "Disable Stealth Mode: " << (stealthDisabled ? "\033[1;32mSUCCESS\033[0m" : "\033[1;31mFAILED\033[0m") << std::endl;
        
        // Test security report
        PrintSeparator("SECURITY REPORT");
        std::cout << manager.GenerateSecurityReport() << std::endl;
        
        // Log inizializzazione
        PrintInitializationLog(manager.GetInitializationLog());
        
        // Test network fingerprint (se disponibile)
        PrintSeparator("NETWORK FINGERPRINT");
        std::string netFingerprint = manager.GetNetworkFingerprint();
        std::cout << "Network Fingerprint: " << netFingerprint << std::endl;
        
        // Attendi un altro po' per vedere i thread in azione
        std::cout << "\nWaiting 5 more seconds to observe monitoring..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        // Shutdown controllato
        PrintSeparator("SHUTDOWN PHASE");
        
        std::cout << "Initiating controlled shutdown..." << std::endl;
        manager.Shutdown();
        
        std::cout << "\n\033[1;32m[SUCCESS]\033[0m Bootstrap manager shutdown completed" << std::endl;
        
        PrintSeparator("TEST COMPLETED SUCCESSFULLY");
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "\n\033[1;31m[EXCEPTION]\033[0m " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "\n\033[1;31m[EXCEPTION]\033[0m Unknown exception caught" << std::endl;
        return 1;
    }
}