#ifndef LIBRARY_EMBEDDER_H
#define LIBRARY_EMBEDDER_H

#include <vector>
#include <string>
#include <cstdint>
#include <map>

namespace EmbedUtils {
    
    struct EmbeddedLibrary {
        std::string name;                    
        std::vector<uint8_t> data;          
        size_t originalSize;                 
        std::string checksum;                
        bool isCompressed;                   

        EmbeddedLibrary() 
            : originalSize(0), isCompressed(false) {}
    };
    
    // Tipo per callback di progresso
    using ProgressCallback = void(*)(const std::string& operation, float progress);
}

class LibraryEmbedder {
public:
    LibraryEmbedder();
    ~LibraryEmbedder();
    
    // Carica libreria da file
    bool LoadLibrary(const std::string& filepath);
    
    // Ottiene i bytes della libreria caricata
    const std::vector<uint8_t>& GetLibraryBytes() const;
    
    // Ottiene informazioni sulla libreria
    const EmbedUtils::EmbeddedLibrary& GetLibraryInfo() const;
    
    // Genera header C++ con array embedded
    bool GenerateHeaderFile(const std::string& outputPath, 
                           const std::string& arrayName = "embedded_lib");
    
    // Genera source C++ con array embedded
    bool GenerateSourceFile(const std::string& outputPath,
                           const std::string& headerName,
                           const std::string& arrayName = "embedded_lib");
    
    // Comprime i dati (opzionale)
    bool CompressData();
    
    // Decomprime i dati
    static std::vector<uint8_t> DecompressData(const std::vector<uint8_t>& compressed);
    
    // Calcola checksum
    static std::string CalculateChecksum(const std::vector<uint8_t>& data);
    
    // Verifica checksum
    static bool VerifyChecksum(const std::vector<uint8_t>& data, const std::string& expectedChecksum);
    
    // Callback per progresso
    void SetProgressCallback(EmbedUtils::ProgressCallback callback);
    
    // Ottiene ultimo errore
    std::string GetLastError() const;
    
    // Reset stato
    void Clear();
    
private:
    EmbedUtils::EmbeddedLibrary m_library;
    EmbedUtils::ProgressCallback m_progressCallback;
    std::string m_lastError;
    
    // Helper per lettura file
    bool ReadFileToBuffer(const std::string& filepath, std::vector<uint8_t>& buffer);
    
    // Helper per scrittura file
    bool WriteBufferToFile(const std::string& filepath, const std::string& content);
    
    // Genera contenuto header
    std::string GenerateHeaderContent(const std::string& arrayName) const;
    
    // Genera contenuto source
    std::string GenerateSourceContent(const std::string& headerName, 
                                     const std::string& arrayName) const;
    
    // Formatta bytes per output C++
    std::string FormatBytesAsCppArray(const std::vector<uint8_t>& data, 
                                     size_t bytesPerLine = 12) const;
    
    void SetError(const std::string& error);
    
    void NotifyProgress(const std::string& operation, float progress);
};

namespace EmbedUtils {
    // Converte bytes in stringa hex
    std::string BytesToHex(const std::vector<uint8_t>& bytes);
    
    // Converte stringa hex in bytes
    std::vector<uint8_t> HexToBytes(const std::string& hex);
    
    std::string GetFilename(const std::string& filepath);
    
    std::string GetExtension(const std::string& filepath);
    
    std::string SanitizeVariableName(const std::string& name);
}

#endif // LIBRARY_EMBEDDER_H