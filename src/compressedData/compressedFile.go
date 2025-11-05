package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Header custom per i nostri binari
type Header struct {
	Magic      uint32 // Signature custom
	Version    uint16
	Flags      uint16
	OrigSize   uint32
	CompSize   uint32
	Checksum   uint32
}

const (
	MAGIC      = 0x4F425343 // "OBSC" in hex
	VERSION    = 0x0001
	BLOCK_SIZE = 4096
	MIN_MATCH  = 3
	MAX_MATCH  = 258
	WINDOW_SIZE = 32768
)

// Chiave per XOR (in produzione usare key derivation)
var xorKey = []byte{0x7A, 0x3F, 0xE2, 0x91, 0x5C, 0xB8, 0x44, 0xD7}

// Obfuscate: XOR + bit shuffling
func obfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	
	// XOR con chiave rotante
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	
	// Bit shuffling: inverti ordine bit di ogni byte
	for i := 0; i < len(result); i++ {
		result[i] = reverseBits(result[i])
	}
	
	return result
}

// Deobfuscate: operazioni inverse
func deobfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	
	// Ripristina ordine bit
	for i := 0; i < len(data); i++ {
		result[i] = reverseBits(data[i])
	}
	
	// XOR (l'operazione è simmetrica)
	for i := 0; i < len(result); i++ {
		result[i] = result[i] ^ xorKey[i%len(xorKey)]
	}
	
	return result
}

func reverseBits(b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		result = (result << 1) | (b & 1)
		b >>= 1
	}
	return result
}

// Compressione LZ77 modificata
func compress(data []byte) []byte {
	var output bytes.Buffer
	pos := 0
	
	for pos < len(data) {
		bestLen := 0
		bestDist := 0
		
		// Cerca match nella finestra
		start := pos - WINDOW_SIZE
		if start < 0 {
			start = 0
		}
		
		for i := start; i < pos; i++ {
			length := 0
			for length < MAX_MATCH && pos+length < len(data) && data[i+length] == data[pos+length] {
				length++
			}
			
			if length > bestLen {
				bestLen = length
				bestDist = pos - i
			}
		}
		
		if bestLen >= MIN_MATCH {
			// Token: <1><distanza:15bit><lunghezza:8bit>
			token := uint32(1<<23) | uint32(bestDist<<8) | uint32(bestLen)
			binary.Write(&output, binary.LittleEndian, token)
			pos += bestLen
		} else {
			// Literal: <0><byte>
			token := uint32(data[pos])
			binary.Write(&output, binary.LittleEndian, token)
			pos++
		}
	}
	
	return output.Bytes()
}

// Decompressione
func decompress(data []byte, origSize int) []byte {
	output := make([]byte, 0, origSize)
	reader := bytes.NewReader(data)
	
	for reader.Len() > 0 {
		var token uint32
		binary.Read(reader, binary.LittleEndian, &token)
		
		if token&(1<<23) != 0 {
			// È un match
			dist := int((token >> 8) & 0x7FFF)
			length := int(token & 0xFF)
			
			start := len(output) - dist
			for i := 0; i < length; i++ {
				output = append(output, output[start+i])
			}
		} else {
			// È un literal
			output = append(output, byte(token&0xFF))
		}
	}
	
	return output
}

// Checksum custom (non CRC standard)
func customChecksum(data []byte) uint32 {
	var sum uint32 = 0x811C9DC5 // FNV offset basis
	for _, b := range data {
		sum ^= uint32(b)
		sum *= 0x01000193 // FNV prime
		sum = (sum << 7) | (sum >> 25) // Rotazione
	}
	return sum
}

// Comprimi e salva file
func CompressFile(inputPath, outputPath string) error {
	// Leggi file originale
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	
	fmt.Printf("File originale: %d bytes\n", len(data))
	
	// 1. Offusca
	obfData := obfuscate(data)
	
	// 2. Comprimi
	compData := compress(obfData)
	
	fmt.Printf("Dopo compressione: %d bytes (%.1f%%)\n", 
		len(compData), float64(len(compData))/float64(len(data))*100)
	
	// 3. Crea header
	header := Header{
		Magic:    MAGIC,
		Version:  VERSION,
		Flags:    0,
		OrigSize: uint32(len(data)),
		CompSize: uint32(len(compData)),
		Checksum: customChecksum(data),
	}
	
	// 4. Scrivi file
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()
	
	binary.Write(output, binary.LittleEndian, header)
	output.Write(compData)
	
	fmt.Printf("File compresso salvato: %s\n", outputPath)
	return nil
}

// Decomprimi file
func DecompressFile(inputPath, outputPath string) error {
	// Leggi file compresso
	file, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Leggi header
	var header Header
	binary.Read(file, binary.LittleEndian, &header)
	
	if header.Magic != MAGIC {
		return fmt.Errorf("file non valido: magic number errato")
	}
	
	fmt.Printf("Decompressione: %d -> %d bytes\n", header.CompSize, header.OrigSize)
	
	// Leggi dati compressi
	compData := make([]byte, header.CompSize)
	io.ReadFull(file, compData)
	
	// 1. Decomprimi
	obfData := decompress(compData, int(header.OrigSize))
	
	// 2. Deoffusca
	origData := deobfuscate(obfData)
	
	// 3. Verifica checksum
	if customChecksum(origData) != header.Checksum {
		return fmt.Errorf("checksum non valido: file corrotto")
	}
	
	// 4. Salva
	err = os.WriteFile(outputPath, origData, 0644)
	if err != nil {
		return err
	}
	
	fmt.Printf("File decompresso salvato: %s\n", outputPath)
	return nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Uso:")
		fmt.Println("  compress <input> <output>   - Comprimi file")
		fmt.Println("  decompress <input> <output> - Decomprimi file")
		os.Exit(1)
	}
	
	cmd := os.Args[1]
	input := os.Args[2]
	output := os.Args[3]
	
	var err error
	switch cmd {
	case "compress":
		err = CompressFile(input, output)
	case "decompress":
		err = DecompressFile(input, output)
	default:
		fmt.Println("Comando non riconosciuto:", cmd)
		os.Exit(1)
	}
	
	if err != nil {
		fmt.Println("Errore:", err)
		os.Exit(1)
	}
}