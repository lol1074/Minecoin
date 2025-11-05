#include "library_embedder.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

// Costruttore
LibraryEmbedder::LibraryEmbedder()
    : m_progressCallback(nullptr)
{
}

// Distruttore
LibraryEmbedder::~LibraryEmbedder()
{
    Clear();
}

// Carica libreria da file
bool LibraryEmbedder::LoadLibrary(const std::string& filepath)
{
    NotifyProgress("Loading library", 0.0f);
    
    // Leggi file
    if (!ReadFileToBuffer(filepath, m_library.data)) {
        SetError("Failed to read file: " + filepath);
        return false;
    }
    
    NotifyProgress("Reading file", 30.0f);
    
    // Imposta informazioni
    m_library.name = EmbedUtils::GetFilename(filepath);
    m_library.originalSize = m_library.data.size();
    m_library.isCompressed = false;
    
    NotifyProgress("Calculating checksum", 60.0f);
    
    // Calcola checksum
    m_library.checksum = CalculateChecksum(m_library.data);
    
    NotifyProgress("Library loaded", 100.0f);
    
    return true;
}

// Ottiene bytes
const std::vector<uint8_t>& LibraryEmbedder::GetLibraryBytes() const
{
    return m_library.data;
}

// Ottiene info
const EmbedUtils::EmbeddedLibrary& LibraryEmbedder::GetLibraryInfo() const
{
    return m_library;
}

// Genera header file
bool LibraryEmbedder::GenerateHeaderFile(const std::string& outputPath, 
                                        const std::string& arrayName)
{
    if (m_library.data.empty()) {
        SetError("No library loaded");
        return false;
    }
    
    NotifyProgress("Generating header", 0.0f);
    
    std::string content = GenerateHeaderContent(arrayName);
    
    NotifyProgress("Writing header", 50.0f);
    
    if (!WriteBufferToFile(outputPath, content)) {
        SetError("Failed to write header file: " + outputPath);
        return false;
    }
    
    NotifyProgress("Header generated", 100.0f);
    
    return true;
}

// Genera source file
bool LibraryEmbedder::GenerateSourceFile(const std::string& outputPath,
                                        const std::string& headerName,
                                        const std::string& arrayName)
{
    if (m_library.data.empty()) {
        SetError("No library loaded");
        return false;
    }
    
    NotifyProgress("Generating source", 0.0f);
    
    std::string content = GenerateSourceContent(headerName, arrayName);
    
    NotifyProgress("Writing source", 50.0f);
    
    if (!WriteBufferToFile(outputPath, content)) {
        SetError("Failed to write source file: " + outputPath);
        return false;
    }
    
    NotifyProgress("Source generated", 100.0f);
    
    return true;
}

// Comprime dati (stub - implementare con zlib se necessario)
bool LibraryEmbedder::CompressData()
{
    if (m_library.data.empty()) {
        SetError("No data to compress");
        return false;
    }
    
    // TODO: Implementare compressione reale (zlib/lz4)
    // Per ora ritorna true senza fare nulla
    m_library.isCompressed = false;
    
    return true;
}

// Decomprime dati (stub)
std::vector<uint8_t> LibraryEmbedder::DecompressData(const std::vector<uint8_t>& compressed)
{
    // TODO: Implementare decompressione reale
    return compressed;
}

// Calcola checksum (SHA-256 semplificato)
std::string LibraryEmbedder::CalculateChecksum(const std::vector<uint8_t>& data)
{
    if (data.empty()) {
        return "";
    }
    
    // Hash semplice (NON crittograficamente sicuro - solo per verifica base)
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV offset basis
    const uint64_t prime = 0x100000001b3ULL; // FNV prime
    
    for (uint8_t byte : data) {
        hash ^= byte;
        hash *= prime;
    }
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    
    return ss.str();
}

// Verifica checksum
bool LibraryEmbedder::VerifyChecksum(const std::vector<uint8_t>& data, 
                                    const std::string& expectedChecksum)
{
    std::string computed = CalculateChecksum(data);
    return computed == expectedChecksum;
}

// Imposta callback
void LibraryEmbedder::SetProgressCallback(EmbedUtils::ProgressCallback callback)
{
    m_progressCallback = callback;
}

// Ottiene errore
std::string LibraryEmbedder::GetLastError() const
{
    return m_lastError;
}

// Clear
void LibraryEmbedder::Clear()
{
    m_library = EmbedUtils::EmbeddedLibrary();
    m_lastError.clear();
}

// ========== PRIVATE METHODS ==========

// Legge file in buffer
bool LibraryEmbedder::ReadFileToBuffer(const std::string& filepath, 
                                      std::vector<uint8_t>& buffer)
{
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    
    if (!file.is_open()) {
        return false;
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    buffer.resize(static_cast<size_t>(size));
    
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return false;
    }
    
    file.close();
    return true;
}

// Scrive buffer in file
bool LibraryEmbedder::WriteBufferToFile(const std::string& filepath, 
                                       const std::string& content)
{
    std::ofstream file(filepath);
    
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    file.close();
    
    return true;
}

// Genera contenuto header
std::string LibraryEmbedder::GenerateHeaderContent(const std::string& arrayName) const
{
    std::stringstream ss;
    std::string guardName = arrayName;
    std::transform(guardName.begin(), guardName.end(), guardName.begin(), ::toupper);
    guardName += "_H";
    
    ss << "// Auto-generated embedded library header\n";
    ss << "// Library: " << m_library.name << "\n";
    ss << "// Size: " << m_library.data.size() << " bytes\n";
    ss << "// Checksum: " << m_library.checksum << "\n\n";
    
    ss << "#ifndef " << guardName << "\n";
    ss << "#define " << guardName << "\n\n";
    
    ss << "#include <cstdint>\n";
    ss << "#include <cstddef>\n\n";
    
    ss << "namespace EmbeddedLibs {\n\n";
    
    ss << "// Library data\n";
    ss << "extern const uint8_t " << arrayName << "_data[];\n";
    ss << "extern const size_t " << arrayName << "_size;\n";
    ss << "extern const char* " << arrayName << "_checksum;\n\n";
    
    ss << "} // namespace EmbeddedLibs\n\n";
    
    ss << "#endif // " << guardName << "\n";
    
    return ss.str();
}

// Genera contenuto source
std::string LibraryEmbedder::GenerateSourceContent(const std::string& headerName,
                                                  const std::string& arrayName) const
{
    std::stringstream ss;
    
    ss << "// Auto-generated embedded library source\n";
    ss << "// Library: " << m_library.name << "\n";
    ss << "// Size: " << m_library.data.size() << " bytes\n\n";
    
    ss << "#include \"" << headerName << "\"\n\n";
    
    ss << "namespace EmbeddedLibs {\n\n";
    
    ss << "// Library binary data (" << m_library.data.size() << " bytes)\n";
    ss << "const uint8_t " << arrayName << "_data[] = {\n";
    ss << FormatBytesAsCppArray(m_library.data);
    ss << "\n};\n\n";
    
    ss << "const size_t " << arrayName << "_size = sizeof(" << arrayName << "_data);\n\n";
    
    ss << "const char* " << arrayName << "_checksum = \"" << m_library.checksum << "\";\n\n";
    
    ss << "} // namespace EmbeddedLibs\n";
    
    return ss.str();
}

// Formatta bytes come array C++
std::string LibraryEmbedder::FormatBytesAsCppArray(const std::vector<uint8_t>& data,
                                                  size_t bytesPerLine) const
{
    std::stringstream ss;
    
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % bytesPerLine == 0) {
            if (i > 0) {
                ss << "\n";
            }
            ss << "    ";
        }
        
        ss << "0x" << std::hex << std::setfill('0') << std::setw(2) 
           << static_cast<int>(data[i]);
        
        if (i < data.size() - 1) {
            ss << ",";
            if ((i + 1) % bytesPerLine != 0) {
                ss << " ";
            }
        }
    }
    
    return ss.str();
}

// Imposta errore
void LibraryEmbedder::SetError(const std::string& error)
{
    m_lastError = error;
}

// Notifica progresso
void LibraryEmbedder::NotifyProgress(const std::string& operation, float progress)
{
    if (m_progressCallback) {
        m_progressCallback(operation, progress);
    }
}

// ========== UTILITY FUNCTIONS ==========

namespace EmbedUtils {

std::string BytesToHex(const std::vector<uint8_t>& bytes)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    std::vector<uint8_t> bytes;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

std::string GetFilename(const std::string& filepath)
{
    size_t pos = filepath.find_last_of("/\\");
    if (pos != std::string::npos) {
        return filepath.substr(pos + 1);
    }
    return filepath;
}

std::string GetExtension(const std::string& filepath)
{
    size_t pos = filepath.find_last_of('.');
    if (pos != std::string::npos && pos < filepath.length() - 1) {
        return filepath.substr(pos + 1);
    }
    return "";
}

std::string SanitizeVariableName(const std::string& name)
{
    std::string sanitized;
    
    for (char c : name) {
        if (std::isalnum(c) || c == '_') {
            sanitized += c;
        } else {
            sanitized += '_';
        }
    }
    
    // Assicura che inizi con lettera o underscore
    if (!sanitized.empty() && std::isdigit(sanitized[0])) {
        sanitized = "_" + sanitized;
    }
    
    return sanitized;
}

} // namespace EmbedUtils