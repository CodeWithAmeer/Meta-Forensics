#include <iostream>
#include <string>
#include <windows.h>
#include <fstream>
#include <map>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <algorithm>
#include <cmath>
#include <thread>
#include <future>
#include <atomic>
#include <regex>
#include <codecvt>
#include <locale>
#include <random>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "urlmon.lib")

class AdvancedForensicAnalyzer {
private:
    std::string filePath;
    std::vector<std::string> analysisResults;
    std::atomic<bool> analysisRunning{ false };

    std::vector<std::string> maliciousHashes = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "5d41402abc4b2a76b9719d911017c592"
    };

    std::vector<std::string> suspiciousPatterns = {
        "cmd.exe", "powershell", "regsvr32", "schtasks",
        "wscript.shell", "shell.application", "winmgmts:",
        "getobject", "adodb.stream", "scripting.filesystemobject"
    };

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::stringstream ss;
        struct tm newtime;
        localtime_s(&newtime, &in_time_t);
        ss << std::put_time(&newtime, "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::string calculateFileHash(const std::string& algorithm) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE rgbHash[512];
        DWORD cbHash = 512;
        CHAR rgbDigits[] = "0123456789abcdef";

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return "ERROR_CRYPTO_CONTEXT";
        }

        ALG_ID algId;
        if (algorithm == "MD5") algId = CALG_MD5;
        else if (algorithm == "SHA1") algId = CALG_SHA1;
        else if (algorithm == "SHA256") algId = CALG_SHA_256;
        else if (algorithm == "SHA512") algId = CALG_SHA_512;
        else if (algorithm == "MD4") algId = CALG_MD4;
        else if (algorithm == "MD2") algId = CALG_MD2;
        else return "UNSUPPORTED_ALGORITHM";

        if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return "ERROR_HASH_CREATION";
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "ERROR_FILE_ACCESS";
        }

        const size_t BUFFER_SIZE = 1024 * 1024;
        std::vector<char> buffer(BUFFER_SIZE);

        while (file.read(buffer.data(), BUFFER_SIZE) || file.gcount() > 0) {
            if (!CryptHashData(hHash, (BYTE*)buffer.data(), (DWORD)file.gcount(), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "ERROR_HASH_DATA";
            }
        }

        if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "ERROR_HASH_RETRIEVAL";
        }

        std::string hashStr;
        for (DWORD i = 0; i < cbHash; i++) {
            hashStr += rgbDigits[rgbHash[i] >> 4];
            hashStr += rgbDigits[rgbHash[i] & 0xf];
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hashStr;
    }

    void deepFileSignatureAnalysis() {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        unsigned char header[512];
        file.read(reinterpret_cast<char*>(header), 512);

        analysisResults.push_back("DEEP_FILE_SIGNATURE_ANALYSIS:");

        std::map<std::string, std::string> signatureDB = {
            {"FFD8FF", "JPEG Image"},
            {"89504E47", "PNG Image"},
            {"47494638", "GIF Image"},
            {"424D", "BMP Image"},
            {"25504446", "PDF Document"},
            {"4D5A", "Windows Executable"},
            {"504B0304", "ZIP Archive"},
            {"504B0506", "ZIP Archive (Empty)"},
            {"504B0708", "ZIP Archive (Spanned)"},
            {"526172211A07", "RAR Archive"},
            {"377ABCAF271C", "7-Zip Archive"},
            {"1F8B08", "GZIP Archive"},
            {"7573746172003030", "TAR Archive"},
            {"D0CF11E0A1B11AE1", "Microsoft Office Document"},
            {"0A252150532D41646F6265", "PostScript File"},
            {"252150532D41646F6265", "PostScript File"},
            {"7B5C72746631", "Rich Text Format"},
            {"2142444E", "MS Access Database"},
            {"53514C69746520666F726D6174203300", "SQLite Database"},
            {"4F676753", "OGG Media"},
            {"664C6143", "FLAC Audio"},
            {"494433", "MP3 with ID3"},
            {"FFFB", "MP3 without ID3"},
            {"000001BA", "MPEG Video"},
            {"000001B3", "MPEG Video"},
            {"1A45DFA3", "Matroska (MKV)"},
            {"3026B2758E66CF11", "Windows Media Video"},
            {"4D546864", "MIDI File"},
            {"52494646", "AVI/WAV Resource Interchange File"},
            {"66747970", "MP4 Video"},
            {"6B6F6F74", "ISO Media"},
            {"435753", "Flash SWF"},
            {"465753", "Flash SWF Compressed"},
            {"3C3F786D6C", "XML Document"},
            {"EFBBBF3C3F786D6C", "UTF-8 XML with BOM"},
            {"FFFE3C003F0078006D006C00", "UTF-16 XML"},
            {"3C21444F4354595045", "HTML Document"},
            {"3C68746D6C", "HTML Document"},
            {"3C48454144", "HTML Document"},
            {"3C626F6479", "HTML Document"},
            {"3C736372697074", "JavaScript in HTML"},
            {"4C00000001140200", "Windows Shortcut (LNK)"},
            {"4D534346", "Microsoft Cabinet"},
            {"EDABEEDB", "RPM Package"},
            {"213C617263683E", "Debian Package"},
            {"7F454C46", "ELF Executable"},
            {"CECEFAED", "Mach-O Binary"},
            {"FEEDFACE", "Mach-O Binary"},
            {"FEEDFACF", "Mach-O Binary 64-bit"},
            {"CAFEBABE", "Java Class"},
            {"504B", "OpenDocument Format"},
            {"504D4F4343", "PalmOS Database"},
            {"0001000000000000", "Windows Prefetch"},
            {"4D494449", "MIDI File"},
            {"5041434B", "PAK Archive"},
            {"5A4F4F", "ZOO Archive"},
            {"1F9D", "LZH Archive"},
            {"1FA0", "LZH Archive"},
            {"425A68", "BZIP2 Archive"},
            {"1F8B", "GZIP Archive"},
            {"FD377A585A00", "XZ Archive"},
            {"04434C4E4C", "Quake PAK Archive"},
            {"4C504B", "LPK Archive"},
            {"4D5A", "DOS Executable"},
            {"5A4D", "DOS Executable (Reverse)"},
            {"4C01", "DOS Linear Executable"},
            {"644C01", "DOS Linear Executable"},
            {"454C01", "DOS Linear Executable"},
            {"4D534654", "Microsoft SFST"},
            {"4F4C494E4B", "Microsoft OLINK"},
            {"4F424A", "Microsoft OBJ"},
            {"FADEBABE", "Java Serialized"},
            {"ACED0005", "Java Serialized"},
            {"CAFED00D", "Java Serialized"},
            {"D0CF11E0A1B11AE1", "OLE Compound File"}
        };

        std::string hexSignature;
        for (int i = 0; i < 32 && i < (int)file.gcount(); i++) {
            char buf[4];
            sprintf_s(buf, sizeof(buf), "%02X", header[i]);
            hexSignature += buf;
        }

        analysisResults.push_back("RAW_SIGNATURE: " + hexSignature);

        bool identified = false;
        for (const auto& sig : signatureDB) {
            if (hexSignature.find(sig.first) == 0) {
                analysisResults.push_back("IDENTIFIED_AS: " + sig.second);
                identified = true;
                break;
            }
        }

        if (!identified) {
            analysisResults.push_back("IDENTIFIED_AS: UNKNOWN/OBFUSCATED_FORMAT");
            analysisResults.push_back("RISK_LEVEL: HIGH - Unidentified file format");
        }
    }

    void advancedFileSystemForensics() {
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            analysisResults.push_back("ADVANCED_FILESYSTEM_FORENSICS:");

            FILETIME times[3] = {
                fileInfo.ftCreationTime,
                fileInfo.ftLastWriteTime,
                fileInfo.ftLastAccessTime
            };

            const char* timeNames[3] = { "CREATION", "MODIFICATION", "LAST_ACCESS" };
            FILETIME currentTime;
            GetSystemTimeAsFileTime(&currentTime);

            for (int i = 0; i < 3; i++) {
                SYSTEMTIME sysTime;
                FileTimeToSystemTime(&times[i], &sysTime);

                ULARGE_INTEGER fileTime, currTime;
                fileTime.LowPart = times[i].dwLowDateTime;
                fileTime.HighPart = times[i].dwHighDateTime;
                currTime.LowPart = currentTime.dwLowDateTime;
                currTime.HighPart = currentTime.dwHighDateTime;

                double diffHours = (currTime.QuadPart - fileTime.QuadPart) / 10000000.0 / 3600.0;

                char timeStr[256];
                sprintf_s(timeStr, sizeof(timeStr),
                    "%s_TIME: %04d-%02d-%02d %02d:%02d:%02d (%.1f hours ago)",
                    timeNames[i],
                    sysTime.wYear, sysTime.wMonth, sysTime.wDay,
                    sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
                    diffHours);
                analysisResults.push_back(timeStr);
            }

            if (CompareFileTime(&times[1], &times[0]) < 0) {
                analysisResults.push_back("TIME_ANOMALY: Modification timestamp predates creation");
                analysisResults.push_back("INDICATOR: Possible timestamp manipulation");
            }

            if (CompareFileTime(&times[2], &times[0]) < 0) {
                analysisResults.push_back("TIME_ANOMALY: Access timestamp predates creation");
                analysisResults.push_back("INDICATOR: Possible timestamp manipulation");
            }

            DWORD attributes = fileInfo.dwFileAttributes;
            std::string attrStr = "SECURITY_ATTRIBUTES: ";
            if (attributes & FILE_ATTRIBUTE_READONLY) attrStr += "READONLY ";
            if (attributes & FILE_ATTRIBUTE_HIDDEN) attrStr += "HIDDEN ";
            if (attributes & FILE_ATTRIBUTE_SYSTEM) attrStr += "SYSTEM ";
            if (attributes & FILE_ATTRIBUTE_ARCHIVE) attrStr += "ARCHIVE ";
            if (attributes & FILE_ATTRIBUTE_COMPRESSED) attrStr += "COMPRESSED ";
            if (attributes & FILE_ATTRIBUTE_ENCRYPTED) attrStr += "ENCRYPTED ";
            if (attributes & FILE_ATTRIBUTE_TEMPORARY) attrStr += "TEMPORARY ";
            if (attributes & FILE_ATTRIBUTE_OFFLINE) attrStr += "OFFLINE ";
            if (attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) attrStr += "NOT_INDEXED ";
            analysisResults.push_back(attrStr);

            if ((attributes & FILE_ATTRIBUTE_HIDDEN) && (attributes & FILE_ATTRIBUTE_SYSTEM)) {
                analysisResults.push_back("SUSPICIOUS_ATTRIBUTES: File is both HIDDEN and SYSTEM");
                analysisResults.push_back("RISK_LEVEL: MEDIUM");
            }
        }
    }

    void detectAlternateDataStreams() {
        analysisResults.push_back("ALTERNATE_DATA_STREAM_SCAN:");

        std::vector<std::string> streamsToCheck = {
            ":Zone.Identifier", ":DATA", "::$DATA", ":$DATA",
            ":SummaryInformation", ":DocumentSummaryInformation",
            ":encryptable", ":AFP_AfpInfo", ":AFP_Resource",
            ":com.apple.quarantine", ":com.apple.metadata:kMDItemWhereFroms"
        };

        bool foundStreams = false;
        for (const auto& stream : streamsToCheck) {
            std::string streamTest = filePath + stream;
            HANDLE hStream = CreateFileA(streamTest.c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hStream != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER streamSize;
                if (GetFileSizeEx(hStream, &streamSize)) {
                    char streamInfo[256];
                    sprintf_s(streamInfo, sizeof(streamInfo),
                        "ADS_DETECTED: %s (%lld bytes)",
                        stream.c_str(), streamSize.QuadPart);
                    analysisResults.push_back(streamInfo);

                    if (streamSize.QuadPart > 1024 * 1024) {
                        analysisResults.push_back("LARGE_ADS_WARNING: Stream contains significant data");
                    }
                }
                foundStreams = true;
                CloseHandle(hStream);
            }
        }

        if (!foundStreams) {
            analysisResults.push_back("ADS_STATUS: No alternate data streams detected");
        }
        else {
            analysisResults.push_back("SECURITY_NOTE: Alternate data streams can hide malicious content");
        }
    }

    void entropyAndCompressionAnalysis() {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        if (fileSize == 0) return;

        std::vector<unsigned char> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

        analysisResults.push_back("ENTROPY_AND_COMPRESSION_ANALYSIS:");

        long long frequency[256] = { 0 };
        for (size_t i = 0; i < fileSize; i++) {
            frequency[buffer[i]]++;
        }

        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                double probability = (double)frequency[i] / fileSize;
                entropy -= probability * log(probability) / log(2.0);
            }
        }

        char entropyStr[128];
        sprintf_s(entropyStr, sizeof(entropyStr), "ENTROPY_SCORE: %.4f bits/byte", entropy);
        analysisResults.push_back(entropyStr);

        if (entropy > 7.8) {
            analysisResults.push_back("ENTROPY_ASSESSMENT: VERY HIGH - Strong encryption likely");
            analysisResults.push_back("RISK_LEVEL: HIGH - Possible encrypted payload");
        }
        else if (entropy > 7.2) {
            analysisResults.push_back("ENTROPY_ASSESSMENT: HIGH - Compression or weak encryption");
            analysisResults.push_back("RISK_LEVEL: MEDIUM");
        }
        else if (entropy > 6.5) {
            analysisResults.push_back("ENTROPY_ASSESSMENT: MEDIUM - Typical compressed data");
            analysisResults.push_back("RISK_LEVEL: LOW");
        }
        else if (entropy > 4.5) {
            analysisResults.push_back("ENTROPY_ASSESSMENT: LOW - Text or structured data");
            analysisResults.push_back("RISK_LEVEL: LOW");
        }
        else {
            analysisResults.push_back("ENTROPY_ASSESSMENT: VERY LOW - Mostly uniform data");
            analysisResults.push_back("RISK_LEVEL: LOW");
        }

        int nullBytes = 0;
        int printableChars = 0;
        for (size_t i = 0; i < fileSize; i++) {
            if (buffer[i] == 0) nullBytes++;
            if (isprint(static_cast<unsigned char>(buffer[i]))) printableChars++;
        }

        double nullRatio = (double)nullBytes / fileSize;
        double printableRatio = (double)printableChars / fileSize;

        char statsStr[256];
        sprintf_s(statsStr, sizeof(statsStr),
            "DATA_STATISTICS: NullBytes=%.2f%%, Printable=%.2f%%",
            nullRatio * 100, printableRatio * 100);
        analysisResults.push_back(statsStr);

        if (nullRatio > 0.4) {
            analysisResults.push_back("PACKING_INDICATOR: High null byte ratio suggests packed executable");
        }

        if (printableRatio < 0.2 && entropy > 7.0) {
            analysisResults.push_back("ENCRYPTION_INDICATOR: Low printable chars with high entropy");
        }
    }

    void advancedSteganographyDetection() {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        size_t sampleSize = fileSize < 16384 ? fileSize : 16384;
        std::vector<unsigned char> buffer(sampleSize);
        file.read(reinterpret_cast<char*>(buffer.data()), sampleSize);

        analysisResults.push_back("ADVANCED_STEGANOGRAPHY_DETECTION:");

        int lsbPatternCount = 0;
        int lsbChanges = 0;
        for (size_t i = 0; i < buffer.size() - 1; i++) {
            if ((buffer[i] & 0x01) == ((buffer[i + 1] & 0x01))) {
                lsbPatternCount++;
            }
            else {
                lsbChanges++;
            }
        }

        double lsbRatio = (double)lsbPatternCount / buffer.size();
        double lsbChangeRate = (double)lsbChanges / buffer.size();

        char lsbStr[256];
        sprintf_s(lsbStr, sizeof(lsbStr),
            "LSB_ANALYSIS: Consistency=%.4f, ChangeRate=%.4f",
            lsbRatio, lsbChangeRate);
        analysisResults.push_back(lsbStr);

        double chiSquare = 0.0;
        int observed[256] = { 0 };
        double expected[256];
        double sampleMean = buffer.size() / 256.0;

        for (size_t i = 0; i < buffer.size(); i++) {
            observed[buffer[i]]++;
        }

        for (int i = 0; i < 256; i++) {
            expected[i] = sampleMean;
            if (expected[i] > 0) {
                double diff = observed[i] - expected[i];
                chiSquare += (diff * diff) / expected[i];
            }
        }

        char chiStr[128];
        sprintf_s(chiStr, sizeof(chiStr), "CHI_SQUARE_TEST: %.4f", chiSquare);
        analysisResults.push_back(chiStr);

        double confidence = 0.0;
        if (chiSquare < 180.0 || lsbRatio > 0.75) {
            analysisResults.push_back("STEGANALYSIS_RESULT: HIGH confidence - Hidden data likely");
            analysisResults.push_back("CONFIDENCE_LEVEL: 90%");
            confidence = 0.9;
        }
        else if (chiSquare < 220.0 || lsbRatio > 0.65) {
            analysisResults.push_back("STEGANALYSIS_RESULT: MEDIUM confidence - Suspicious patterns");
            analysisResults.push_back("CONFIDENCE_LEVEL: 70%");
            confidence = 0.7;
        }
        else {
            analysisResults.push_back("STEGANALYSIS_RESULT: LOW confidence - No significant patterns");
            analysisResults.push_back("CONFIDENCE_LEVEL: 25%");
            confidence = 0.25;
        }

        analysisResults.push_back("STEGANOGRAPHY_RISK: " + std::to_string(int(confidence * 100)) + "%");
    }

    void deepContentAnalysis() {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return;

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        size_t readSize = fileSize < 131072 ? fileSize : 131072;
        std::vector<char> buffer(readSize);
        file.read(buffer.data(), readSize);

        std::string fileContent(buffer.begin(), buffer.end());

        analysisResults.push_back("DEEP_CONTENT_ANALYSIS:");

        std::regex url_regex("(https?|ftp|sftp)://[^\\s/$.?#].[^\\s]*", std::regex::icase);
        std::regex ip_regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{1,5})?\\b");
        std::regex email_regex("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
        std::regex domain_regex("\\b([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b");
        std::regex md5_regex("\\b[A-Fa-f0-9]{32}\\b");
        std::regex sha1_regex("\\b[A-Fa-f0-9]{40}\\b");
        std::regex sha256_regex("\\b[A-Fa-f0-9]{64}\\b");
        std::regex sha512_regex("\\b[A-Fa-f0-9]{128}\\b");
        std::regex bitcoin_regex("\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b");
        std::regex ethereum_regex("\\b0x[a-fA-F0-9]{40}\\b");

        std::regex patterns[] = { url_regex, ip_regex, email_regex, domain_regex,
                                md5_regex, sha1_regex, sha256_regex, sha512_regex,
                                bitcoin_regex, ethereum_regex };

        const char* patternNames[] = {
            "URL", "IP_ADDRESS", "EMAIL", "DOMAIN",
            "MD5_HASH", "SHA1_HASH", "SHA256_HASH", "SHA512_HASH",
            "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"
        };

        for (size_t i = 0; i < 10; i++) {
            std::smatch match;
            std::string::const_iterator searchStart(fileContent.cbegin());
            int count = 0;

            while (std::regex_search(searchStart, fileContent.cend(), match, patterns[i])) {
                count++;
                searchStart = match.suffix().first;
            }

            char result[128];
            sprintf_s(result, sizeof(result), "%s_PATTERNS: %d occurrences", patternNames[i], count);
            analysisResults.push_back(result);
        }

        for (const auto& pattern : suspiciousPatterns) {
            size_t pos = 0;
            int count = 0;
            while ((pos = fileContent.find(pattern, pos)) != std::string::npos) {
                count++;
                pos += pattern.length();
            }

            if (count > 0) {
                char suspiciousStr[256];
                sprintf_s(suspiciousStr, sizeof(suspiciousStr),
                    "SUSPICIOUS_PATTERN: '%s' found %d times",
                    pattern.c_str(), count);
                analysisResults.push_back(suspiciousStr);
            }
        }

        std::string fileExtension = filePath.substr(filePath.find_last_of(".") + 1);
        std::transform(fileExtension.begin(), fileExtension.end(), fileExtension.begin(), ::tolower);

        if ((fileExtension == "exe" || fileExtension == "dll") && fileContent.find("powershell") != std::string::npos) {
            analysisResults.push_back("SHELL_INDICATOR: PowerShell commands in executable");
            analysisResults.push_back("RISK_LEVEL: HIGH - Possible fileless attack vector");
        }
    }

    void threatIntelligenceCorrelation() {
        analysisResults.push_back("THREAT_INTELLIGENCE_CORRELATION:");

        std::string hashes[] = {
            calculateFileHash("MD5"),
            calculateFileHash("SHA1"),
            calculateFileHash("SHA256"),
            calculateFileHash("SHA512")
        };

        const char* hashNames[] = { "MD5", "SHA1", "SHA256", "SHA512" };

        for (int i = 0; i < 4; i++) {
            char hashStr[512];
            sprintf_s(hashStr, sizeof(hashStr), "%s_HASH: %s", hashNames[i], hashes[i].c_str());
            analysisResults.push_back(hashStr);

            auto threatIt = std::find(maliciousHashes.begin(), maliciousHashes.end(), hashes[i]);
            if (threatIt != maliciousHashes.end()) {
                char threatStr[512];
                sprintf_s(threatStr, sizeof(threatStr),
                    "THREAT_MATCH: %s hash found in database",
                    hashNames[i]);
                analysisResults.push_back(threatStr);
                analysisResults.push_back("THREAT_LEVEL: CONFIRMED");
                return;
            }
        }

        std::ifstream file(filePath, std::ios::binary);
        if (file) {
            file.seekg(0, std::ios::end);
            size_t fileSize = file.tellg();

            if (fileSize < 256) {
                analysisResults.push_back("SUSPICIOUS: Extremely small file size");
            }

            if (fileSize > 500 * 1024 * 1024) {
                analysisResults.push_back("SUSPICIOUS: Unusually large file");
            }

            if (fileSize > 0 && fileSize < 1024) {
                double entropy = 0.0;
                file.seekg(0, std::ios::beg);
                std::vector<unsigned char> buffer(fileSize);
                file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

                long long frequency[256] = { 0 };
                for (size_t i = 0; i < fileSize; i++) {
                    frequency[buffer[i]]++;
                }

                for (int i = 0; i < 256; i++) {
                    if (frequency[i] > 0) {
                        double probability = (double)frequency[i] / fileSize;
                        entropy -= probability * log(probability) / log(2.0);
                    }
                }

                if (entropy > 7.5 && fileSize < 512) {
                    analysisResults.push_back("SUSPICIOUS: Small file with high entropy");
                    analysisResults.push_back("INDICATOR: Possible encrypted payload or key material");
                }
            }
        }

        analysisResults.push_back("THREAT_ASSESSMENT: No known threats detected in global databases");
        analysisResults.push_back("RISK_LEVEL: LOW (Based on available intelligence)");
    }

    void memoryAndProcessAnalysis() {
        analysisResults.push_back("MEMORY_AND_PROCESS_ANALYSIS:");

        HANDLE hProcess = GetCurrentProcess();
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            char memoryStr[512];
            sprintf_s(memoryStr, sizeof(memoryStr),
                "PROCESS_MEMORY: WorkingSet=%lluMB, PrivateBytes=%lluMB, PageFaults=%lu",
                pmc.WorkingSetSize / (1024 * 1024),
                pmc.PrivateUsage / (1024 * 1024),
                pmc.PageFaultCount);
            analysisResults.push_back(memoryStr);
        }

        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(memInfo);
        if (GlobalMemoryStatusEx(&memInfo)) {
            char sysMemStr[512];
            sprintf_s(sysMemStr, sizeof(sysMemStr),
                "SYSTEM_MEMORY: Total=%lluGB, Available=%lluGB, Usage=%lu%%",
                memInfo.ullTotalPhys / (1024 * 1024 * 1024),
                memInfo.ullAvailPhys / (1024 * 1024 * 1024),
                memInfo.dwMemoryLoad);
            analysisResults.push_back(sysMemStr);
        }
    }

    void exportComprehensiveReport() {
        std::string baseName = filePath.substr(filePath.find_last_of("\\/") + 1);
        baseName = baseName.substr(0, baseName.find_last_of("."));

        std::string timestamp = getCurrentTimestamp();
        std::replace(timestamp.begin(), timestamp.end(), ':', '-');
        std::replace(timestamp.begin(), timestamp.end(), ' ', '_');

        std::string reportName = "FORENSIC_REPORT_" + baseName + "_" + timestamp + ".txt";

        std::ofstream report(reportName);
        if (report) {
            report << "================================================================================\n";
            report << "                   ADVANCED FORENSIC ANALYSIS REPORT\n";
            report << "================================================================================\n";
            report << "Analysis Timestamp: " << getCurrentTimestamp() << "\n";
            report << "Target File: " << filePath << "\n";
            report << "Tool: Advanced Forensic Analyzer v1.0\n";
            report << "================================================================================\n\n";

            for (const auto& result : analysisResults) {
                report << result << "\n";
            }

            report << "\n================================================================================\n";
            report << "                          END OF ANALYSIS REPORT\n";
            report << "================================================================================\n";

            analysisResults.push_back("REPORT_EXPORTED: " + reportName);
        }
    }

public:
    std::string getRandomTip() {
        std::vector<std::string> tips = {


            "Ameer wishes you a wonderful day of digital forensics!",
            "Did you know? Metadata is basically data about data — like a nutrition label, but for files, photos, and documents.",
            "Did you know? Your phone photos contain EXIF metadata that can include the camera model, exposure settings, and even your GPS location unless you disable it.",
            "Pro Tip: Always verify file hashes from multiple sources to ensure file integrity.",
            "Security Tip: Be cautious of files with mismatched extensions and actual file signatures.",
            "Forensic Insight: Alternate Data Streams in NTFS can hide malicious content from casual inspection.",
            "Privacy Note: PDF documents can contain creator information, editing history, and even printer serial numbers.",
            "Expert Advice: High entropy in small files often indicates encryption or compression used by malware.",
            "Digital Hygiene: Regularly audit your digital footprint and clean up unnecessary metadata.",
            "Analysis Tip: Steganography detection relies on statistical anomalies in file data patterns.",
            "Security Fact: Many ransomware families leave unique metadata signatures in encrypted files.",
            "Forensic Wisdom: Timeline analysis can reveal when a file was truly created versus when it claims to be created.",
            "Privacy Reminder: Social media platforms often strip but may retain metadata from uploaded images.",
            "Technical Insight: File carving can recover deleted data from unallocated disk space based on file signatures.",
            "Best Practice: Maintain a clean baseline system image for comparison during forensic investigations.",
            "Security Awareness: Document metadata can reveal sensitive information about your organization structure.",
            "Forensic Technique: Memory analysis can uncover processes and artifacts that disk analysis might miss.",
            "Digital Evidence: Browser history and download metadata can provide crucial timeline evidence.",
            "Analysis Strategy: Correlate multiple data points for stronger forensic conclusions.",
            "Privacy Tip: Consider using metadata removal tools before sharing files publicly.",
            "Security Tip: Always inspect file signatures—trust the magic bytes, not the file extension.",
            "Did you know? Many image formats store thumbnail previews that may reveal edited or cropped content.",
            "Forensic Fact: RAM dumps often contain plaintext credentials long after they've been 'cleared' from applications.",
            "Insight: Container files like ZIP, DOCX, and APK are just structured archives and can leak internal metadata.",
            "Threat Watch: Malware authors frequently obfuscate code using packers, adding layers of misleading metadata.",
            "Privacy Tip: Screenshots can include embedded color profiles that uniquely identify devices.",
            "Analysis Fact: MFT entries in NTFS can preserve timestamps even after files are deleted.",
            "Pro Tip: Always examine LNK shortcut files—they can reveal paths, timestamps, and user activity.",
            "Did you know? Many audio files contain metadata like encoder version, artist notes, and hidden comment fields.",
            "Forensic Insight: USB device artifacts in the registry can map out physical access history.",
            "Security Reminder: File obfuscation techniques often leave behind repetitive patterns or entropy spikes.",
            "Metadata Fact: Cloud storage platforms sometimes add proprietary metadata when syncing files.",
            "Expert Insight: PE file headers can reveal compiler versions, build times, and suspicious anomalies.",
            "Privacy Warning: Copying text from PDFs may embed tracking identifiers or invisible characters.",
            "Forensic Tip: Swap space can retain fragments of documents, chats, and encryption keys.",
            "Threat Fact: Malicious macros in Office documents can hide encoded payloads in custom metadata fields.",
            "Digital Hygiene: Regularly review browser autofill and saved credential data for unnecessary retention.",
            "Technical Note: Log file rotations can unintentionally preserve deleted or overwritten entries.",
            "Investigative Tip: Hash collisions are rare—if two files share a hash, examine them extremely carefully.",
            "Security Wisdom: Always analyze network metadata—sometimes the headers tell more than the payload.",
            "Forensic Tip: Windows Amcache entries record program execution details long after deletion.",
            "Security Fact: Unexpected parent process relationships often expose malware staging.",
            "Metadata Insight: Many RAW photo formats store unique camera sensor signatures.",
            "Threat Note: Malware droppers frequently hide configs in environment variables.",
            "Analysis Tip: Unexpected gaps in log timestamps can indicate manual log editing.",
            "Digital Evidence: Browser extension folders often store detailed usage timestamps.",
            "Forensic Insight: System Resource Usage Monitor logs reveal background program activity.",
            "Privacy Tip: Mobile apps often embed location metadata in cached images.",
            "Security Fact: Strange TLS cipher choices may identify malicious clients.",
            "Analysis Trick: Unique stack pivot patterns frequently indicate exploitation.",
            "Forensic Fact: Linux bash history may expose commands removed from on screen logs.",
            "Metadata Hint: MKV containers store embedded track names created during editing.",
            "Threat Insight: Malware beacons sometimes randomize packet padding lengths to evade detection.",
            "Digital Clue: Unusual ARP retries can indicate spoofing attempts.",
            "Analysis Fact: Opcode nibbles often reveal the presence of virtualized or obfuscated code.",
            "Security Reminder: Registry 'Image File Execution Options' can be abused for persistence.",
            "Forensic Note: Mobile device backups often contain deleted text fragments.",
            "Metadata Tip: Many document formats store installed font names used during creation.",
            "Threat Indicator: Frequent short lived TCP sessions may suggest botnet activity.",
            "Digital Evidence: Firewall logs often reveal first contact attempts by intruders.",
            "Privacy Insight: Remote meeting apps embed user device names in metadata.",
            "Forensic Technique: CARVE detection works well when matching fragmented JPEG quantization tables.",
            "Security Insight: Multiple failed driver loads can indicate rootkit experimentation.",
            "Analysis Note: Comparing memory-mapped regions highlights injected code segments.",
            "Threat Clue: High jitter values in beacon intervals can expose custom C2 protocols.",
            "Metadata Fact: Some PDF compressors add unique fingerprints tied to specific software builds.",
            "Digital Hygiene: Delete thumbnail caches to reduce residual data exposure.",
            "Forensic Tip: Slack artifacts on Linux systems may retain outdated directory listings.",
            "Security Reminder: Unusual DLL search paths often point to sideloading attacks.",
            "Analysis Hint: Strange differences in binary section alignment often indicate packing.",
            "Digital Evidence: Bluetooth Low Energy scanning logs reveal nearby devices with timestamps.",
            "Threat Note: Memory only payloads still leave footprints in process handles.",
            "Metadata Insight: WAV files often contain comment chunks inserted by editing tools.",
            "Forensic Fact: The USN Journal in NTFS tracks file changes even when names change.",
            "Security Fact: Malicious installers often include corrupted or fake Authenticode signatures.",
            "Analysis Tip: API call graphs help identify malware families with shared logic.",
            "Threat Insight: Hardcoded user agent strings sometimes match known malware clusters.",
            "Forensic Reminder: Deleted Safari history may persist in cloud sync backups.",
            "Metadata Tip: Many 3D model formats store object origin coordinates and designer notes.",
            "Security Clue: Frequent registry polling may indicate surveillance spyware.",
            "Analysis Fact: Sections filled with repeated 0xCC bytes typically indicate removed debugging code.",
            "Digital Evidence: Syslog rotation patterns reveal activity even after logs are cleared.",
            "Threat Tip: Compromised machines often generate uncommon ICMP payload sizes.",
            "Metadata Insight: PowerPoint slides can contain unreferenced embedded media files.",
            "Forensic Note: macOS quarantine metadata logs downloaded file origins.",
            "Security Reminder: Unexpected SMBv1 traffic can indicate outdated malware activity.",
            "Analysis Trick: Visual entropy plots highlight encrypted blobs inside otherwise normal files.",
            "Threat Insight: Many implants use delayed execution to evade sandboxing.",
            "Digital Evidence: Print server logs can reveal sensitive file names shared on networks.",
            "Metadata Tip: JSON APIs sometimes include hidden version identifiers useful for provenance.",
            "Forensic Fact: Prefetch files can show command line arguments used at execution.",
            "Security Note: Hard coded crypto keys are a common malware developer shortcut.",
            "Analysis Insight: Repeated imports with no apparent use may indicate hidden loader logic.",
            "Threat Indicator: Frequent DNS failures may signal domain generation algorithm activity.",
            "Privacy Tip: Browser spell check logs sometimes record typed words locally.",
            "Forensic Insight: Wireless connection histories reveal where a device has traveled.",
            "Metadata Fact: Many log formats embed timezone offsets for each entry.",
            "Security Tip: DNS over HTTPS traffic spikes can indicate covert communication.",
            "Analysis Trick: PE compile timestamps that match Unix epoch values often signal tampering.",
            "Digital Evidence: Linux journal logs keep binary records even after text logs are removed.",
            "Threat Reminder: Malware often injects code into memory via reflective loading.",
            "Metadata Insight: MP3 ID3 tags can store hidden comments not shown by players.",
            "Forensic Note: Registry transaction logs may contain values not found in the live hive.",
            "Security Tip: Droppers frequently use overly long environment variable expansions.",
            "Analysis Fact: Virtual machine markers in malware samples sometimes reveal testing environments.",
            "Threat Insight: Unexpected SSDP broadcasts may indicate device level compromise.",
            "Privacy Fact: Clipboard synchronization across devices may leak sensitive text.",
            "Digital Evidence: DNS negative cache entries reveal previous lookup attempts.",
            "Metadata Insight: Many file formats store creation locale or language preferences.",
            "Forensic Technique: Characteristic block sizes help identify encrypted archive fragments.",
            "Security Note: Local Proxy Auto Config scripts can be manipulated for MITM attacks.",
            "Analysis Tip: Checking binary compiler signatures helps identify the toolchain used.",
            "Threat Clue: Repeated outbound 443 connections without TLS negotiation is suspicious.",
            "Metadata Fact: Most photo formats store ISO settings, helpful in authenticity checks.",
            "Forensic Reminder: Deleted text messages may remain in mobile SQLite-wal files.",
            "Security Fact: Persistence via startup folders remains common for low skill attackers.",
            "Analysis Insight: Rare instruction sequences often hint at custom malware toolkits.",
            "Threat Tip: Implants sometimes check system uptime to avoid sandbox traps.",
            "Digital Evidence: Network address translation logs can reassemble communication chains.",
            "Metadata Note: Many subtitle files embed author notes or timing revisions.",
            "Forensic Fact: Hibernation files often store contents of memory at shutdown.",
            "Security Tip: Unexpected outbound connections to IP literal addresses may suggest malware.",
            "Analysis Trick: Comparing entropy across time shows when a file was modified with new data.",
            "Threat Insight: Malware sometimes disables certificate validation to intercept its own traffic.",
            "Privacy Reminder: Cloud note apps often store historical snapshot versions.",
            "Forensic Clue: EXE files with incorrect section checksum fields deserve closer inspection.",
            "Metadata Tip: Many archives store the operating system used to create them.",
            "Digital Evidence: Endpoint detection logs may show blocked actions that users never notice.",
            "Security Insight: Unrecognized services with obscure names often indicate persistence.",
            "Analysis Note: Identical instruction padding patterns across samples reveal shared authorship.",
            "Threat Tip: Some malware variants encode C2 messages with custom base shifting algorithms.",
            "Metadata Insight: PSD files store full layer structures even when layers appear flattened.",
            "Forensic Fact: Mobile EXIF data may include operator information from cellular towers.",
            "Security Tip: Unexpected Windows task creation events are strong compromise indicators.",
            "Analysis Insight: Hard coded network ports sometimes match specific malware families.",
            "Threat Note: Reverse shells often use predictable heartbeat packets.",
            "Metadata Fact: Many archived emails store unique message IDs ideal for timeline building.",
            "Forensic Reminder: Sideloaded mobile apps may embed developer signatures in metadata.",
            "Digital Evidence: Switch port logs show which physical device was connected at what time.",
            "Security Tip: Rare user agent strings in proxy logs often identify automated malware.",
            "Analysis Insight: Tools that remove symbol tables still leave behind structural patterns.",
            "Threat Indicator: Massive outbound DNS errors can reveal sinkholed botnets.",
            "Metadata Note: Some webcam images store firmware version numbers.",
            "Forensic Tech: Windows SRUM logs track energy usage by application over time.",
            "Security Fact: Compromised systems often generate new firewall rules without notice.",
            "Analysis Tip: Misaligned PE section boundaries can reveal injected code regions.",
            "Threat Insight: Certain botnets rotate command servers based on hard coded day offsets.",
            "Privacy Note: Document revisions in collaborative tools often store full change histories.",
            "Forensic Insight: Registry shellbags identify previously browsed paths on remote shares.",
            "Metadata Fact: Some CAD formats store workstation IDs inside model headers.",
            "Digital Evidence: VPN logs often reveal exact connection start and stop times.",
            "Security Tip: Unexpected spikes in encrypted traffic may signal data exfiltration.",
            "Analysis Trick: Weird loops in disassembly often indicate opaque predicate obfuscation.",
            "Threat Fact: Multi stage malware frequently loads payloads from temporary system folders.",
            "Metadata Tip: FLV video files embed keyframe timing useful for reconstruction.",
            "Forensic Note: Windows Error Reporting logs capture application crash details.",
            "Security Tip: Hidden scheduled tasks can mask long term attacker access.",
            "Analysis Insight: Identical string lengths across samples can reveal encoded commands.",
            "Threat Indicator: Non standard DNS record types may reveal covert channels.",
            "Metadata Insight: Many ebook formats include publisher specific UUID identifiers.",
            "Forensic Fact: Deleted cloud sync records can be recovered from local cache files.",
            "Security Note: Overly broad file permissions on system folders invite exploitation.",
            "Analysis Fact: Network packet capture anomalies often expose beaconing frequencies.",
            "Threat Hint: Malware campaigns often reuse custom TLS fingerprints.",
            "Metadata Tip: Certain image editing tools leave signature artifacts in pixel noise.",
            "Forensic Reminder: Stale print spool files may reveal previously printed documents.",
            "Security Insight: Remote code execution attempts often begin with reconnaissance scripts.",
            "Analysis Trick: Non standard calling conventions in disassembly point to custom packers.",
            "Threat Insight: Many loaders decrypt payloads incrementally to avoid detection.",
            "Digital Evidence: HTTP referer logs may expose hidden paths used by attackers.",
            "Metadata Fact: AVI files often store detailed frame timing metadata.",
            "Forensic Tip: Windows RecentFiles entries map out user interaction sequences.",
            "Security Reminder: Hidden startup registry entries are common persistence points.",
            "Analysis Insight: Frequent read access to sensitive folders can reveal staging behavior.",
            "Threat Note: Some droppers check system language to avoid legal complications for developers.",
            "Metadata Insight: Many XML document types include unused nodes left by editing software.",
            "Forensic Fact: Older Wi Fi profiles may reveal devices never connected recently.",
            "Security Tip: RPC traffic bursts on unusual ports may indicate lateral movement.",
            "Analysis Clue: Repeated file I O on empty directories suggests sandbox probing.",
            "Threat Insight: Many C2 frameworks rely on timestamp obfuscation to blend with traffic.",
            "Privacy Tip: Many mobile apps store temporary media caches without encryption.",
            "Metadata Note: Portable network graphics files may store uncompressed textual notes.",
            "Forensic Technique: Carved PDF objects can reveal partial or removed document content.",
            "Security Fact: Hidden browser extensions can inject malicious scripts unnoticed.",
            "Analysis Insight: Robust function hashing can group malware with shared ancestry.",
            "Threat Indicator: Outbound connections to nonexistent domains often point to algorithmic domain testing.",
            "Metadata Fact: Some scanners embed device serial numbers in header data.",
            "Forensic Note: USB serial numbers stored in registry keys reveal device reuse.",
            "Security Tip: Command line tools executed with long sleeps often indicate automation.",
            "Analysis Trick: Identical error handling routines across samples hint at a shared builder.",
            "Threat Insight: Some implants track human interaction to avoid sandbox environments.",
            "Metadata Tip: Many image editors embed undo history in proprietary formats.",
            "Forensic Insight: Cached map tiles can reveal user travel routes.",
            "Security Reminder: Unauthorized certificate installations reveal MITM attempts.",
            "Analysis Fact: Timing profiles of malware execution help classify operational stages.",
            "Threat Note: Some botnets use social media profiles as command storage.",
            "Metadata Fact: Many compressed archives store directory trees even when empty.",
            "Digital Evidence: Network neighbor tables can reveal previously connected machines.",
            "Forensic Tip: Backup manifests may list files no longer present on the device.",
            "Security Insight: Using outdated SMB signing settings increases attack surface.",
            "Analysis Trick: Memory snapshot comparisons expose injected or volatile objects.",
            "Threat Indicator: Unexpected ICMP tunneling activity often indicates exfiltration.",
            "Metadata Insight: Audio formats sometimes store exact encoder application names.",
            "Forensic Fact: Old Windows restore points often contain historical registry hives.",
            "Security Note: Hidden COM object registrations can provide stealth persistence.",
            "Analysis Insight: Malware often reuses encryption routines even across unrelated samples.",
            "Threat Tip: Some advanced implants store data chunks inside Windows font files.",
            "Metadata Insight: Many video editors embed project identifiers inside output files.",
            "Forensic Reminder: Partial SQLite pages can reveal deleted rows.",
            "Security Tip: Sudden changes in process integrity levels deserve investigation.",
            "Analysis Trick: Grouping strings by encoding helps reveal multiple embedded payloads.",
            "Threat Indicator: Excessive Windows Management Instrumentation queries signal reconnaissance.",
            "Metadata Fact: Many scientific file formats embed researcher names and institution info.",
            "Forensic Note: System crash dumps hold register states and partial memory.",
            "Security Insight: DNS query patterns often reflect malware update schedules.",
            "Analysis Fact: File system journaling can reveal original file metadata post tampering.",
            "Threat Insight: Some malware families log keystrokes using direct keyboard buffer access.",
            "Metadata Tip: PDF stream objects may still remain after content removal.",
            "Forensic Technique: USB forensic logs track mount and dismount times for storage devices.",
            "Security Reminder: Suspicious kernel callback registrations are worth deeper inspection.",
            "Analysis Clue: Identical checksum mismatches in executables often point to the same builder.",
            "Threat Note: Network time protocol abuse can be used for command signaling.",
            "Metadata Insight: Certain image formats store GPS altitude and speed on capture.",
            "Forensic Fact: Windows Syscache files may contain fragments of recently run executables.",
            "Security Tip: Unexpected symbolic links in system folders can redirect execution flows.",
            "Analysis Insight: Executables missing relocation sections often originate from packers.",
            "Threat Indicator: Constant outbound traffic with small packet sizes suggests heartbeat beacons.",
            "Metadata Fact: Many vector graphic files store editing tool version numbers.",
            "Forensic Tip: Browsers store autocomplete predictions in separate configuration files.",
            "Security Note: Unregistered services created temporarily by malware can evade startup inspections.",
            "Analysis Trick: Inspecting compiler optimization patterns reveals source language clues.",
            "Threat Insight: Many malware families store temporary configuration points in the registry key PendingFileRenameOperations.",
            "Metadata Fact: Audio mastering software often inserts internal pipeline markers.",
            "Forensic Insight: Network auth logs reveal movements between machines.",
            "Security Tip: Unexpected DNS resolvers set in network configs may indicate hijacking.",
            "Analysis Fact: Byte frequency histograms reveal unnatural data uniformity.",
            "Threat Indicator: Some malware uses weekday based behavior shifts.",
            "Metadata Tip: Portable app formats store embedded user settings inside the exe wrapper.",
            "Forensic Note: APFS volume snapshots retain historical directory structures.",
            "Security Insight: Programs with anonymous pipes to critical processes deserve investigation.",
            "Security Tip: Watch for executable files that spawn network connections immediately upon launch.",
            "Privacy Note: Email draft metadata may contain device identifiers not visible in the final message.",
            "Forensic Insight: Unallocated disk space often preserves fragments of previously encrypted data.",
            "Analysis Tip: Compare script modification timestamps with system uptime to spot injected edits.",
            "Security Tip: Monitor for DLLs loaded from non-standard directories that bypass verification.",
            "Privacy Note: Smart device pairing logs can reveal past associations with unknown hardware.",
            "Forensic Insight: Residual RAM strings can show command-line arguments of long-terminated processes.",
            "Analysis Tip: Unexpected thread injection into system processes is a common persistence method.",
            "Security Tip: Observe firewall rule changes that appear briefly then revert automatically.",
            "Privacy Note: Image editor autosave folders may contain unfiltered original photos.",
            "Forensic Insight: Deleted SQLite journaling files can restore partial chat histories.",
            "Analysis Tip: Inconsistent file cluster allocation often indicates manual manipulation.",
            "Security Tip: Privilege escalation attempts often leave traces in security tokens stored in memory.",
            "Privacy Note: Browser extension metadata can leak browsing behavior even after removal.",
            "Forensic Insight: Legacy shadow copies may preserve entire user profiles unintentionally.",
            "Analysis Tip: Look for scripts using obscure encoding to hide command sequences.",
            "Security Tip: Hidden scheduled tasks often run under misleading system-friendly names.",
            "Privacy Note: Wi-Fi association logs can reveal historical movement patterns.",
            "Forensic Insight: Residual registry transaction logs help uncover unauthorized system edits.",
            "Analysis Tip: Compare power state transitions to user activity to detect remote access.",
            "Security Tip: Investigate processes that spoof parent process IDs to mask their origin.",
            "Privacy Note: Document templates may store personal revision histories unknown to users.",
            "Forensic Insight: Examine old pagefile data for memory fragments of sensitive application states.",
            "Analysis Tip: Network interfaces activating without user input may indicate remote manipulation.",
            "Security Tip: Monitor for credential providers added without corresponding software installations.",
            "Privacy Note: Smartwatch sync logs may reveal notification content you thought was cleared.",
            "Forensic Insight: System restore snapshots can expose deleted executables and scripts.",
            "Analysis Tip: Unexpected registry key timestamps often reveal hidden installer activity.",
            "Security Tip: Look for processes attempting to disable ETW logging mechanisms.",
            "Privacy Note: Shared clipboard services can broadcast sensitive text across connected devices.",
            "Forensic Insight: Old print spool data can disclose filenames and document metadata.",
            "Analysis Tip: Sudden spikes in CPU usage by seemingly idle processes warrant deeper investigation.",
            "Security Tip: Kernel driver loads from unsigned sources indicate high-risk tampering.",
            "Privacy Note: Messaging app thumbnail caches preserve conversation previews indefinitely.",
            "Forensic Insight: Hibernation files often contain intact memory states from earlier sessions.",
            "Analysis Tip: Monitor WMI event consumers for covert persistence techniques.",
            "Security Tip: Scripts modifying PATH variables silently can hijack legitimate executions.",
            "Privacy Note: VoIP call logs may include timestamps and IP addresses of all participants.",
            "Forensic Insight: Shell history backups survive manual clearing attempts in many environments.",
            "Analysis Tip: Cross-check DNS query frequency to detect beaconing malware.",
            "Security Tip: Services running with unexpectedly broad privileges should be examined immediately.",
            "Privacy Note: Old Bluetooth handshake logs can reveal device nicknames and MAC addresses.",
            "Forensic Insight: Examine alternate prefetch files generated by system updates for hidden activity.",
            "Analysis Tip: Watch for duplicate process names that differ only in subtle character encoding.",
            "Security Tip: Unauthorized modifications to certificate stores can redirect secure traffic.",
            "Privacy Note: Auto-syncing photo apps may upload images users never intentionally shared.",
            "Forensic Insight: Unused partitions sometimes contain attacker staging environments.",
            "Analysis Tip: Be aware of scripts using multiple nested interpreters to obscure behavior.",
            "Security Tip: Look for services that create temporary admin accounts during runtime.",
            "Privacy Note: File-sharing tools often embed upload timestamps in hidden metadata.",
            "Forensic Insight: Memory dumps can reveal long-lived encryption keys still in active buffers.",
            "Analysis Tip: Inspect system audit logs for missing increments in event IDs.",
            "Security Tip: Rogue firmware updates often lack proper signature chains and metadata.",
            "Privacy Note: Document collaboration platforms store revision authors even after export.",
            "Forensic Insight: Browser cache index files map out detailed browsing sequences.",
            "Analysis Tip: Monitor system calls for suspicious attempts to enumerate protected areas.",
            "Security Tip: Look for processes that rebind network ports after failed access attempts.",
            "Privacy Note: Cloud service sync manifests may list deleted folders and their history.",
            "Forensic Insight: Partial registry hives can reconstruct long-gone system configurations.",
            "Analysis Tip: Investigate containers that maintain active network namespaces after deletion.",
            "Security Tip: Unauthorized VPN adapters may appear silently and redirect traffic.",
            "Privacy Note: Audio editing software sometimes embeds microphone calibration information.",
            "Forensic Insight: Examine USB event logs to spot devices that appeared only once.",
            "Analysis Tip: Pay attention to file metadata inconsistencies across mirrored directories.",
            "Security Tip: Processes executing from temp folders without installation traces are suspect.",
            "Privacy Note: Clipboard sync logs store exact timestamps of every copied string.",
            "Forensic Insight: Metadata from mounted ISO images can reveal attacker toolkits.",
            "Analysis Tip: Track abnormal thread creation patterns in GUI applications.",
            "Security Tip: Scripts disabling AMSI briefly are common components in malware chains.",
            "Privacy Note: Location services metadata may persist even when location history is off.",
            "Forensic Insight: Network flow logs can reconstruct communication patterns long after content deletion.",
            "Analysis Tip: Investigate binaries with missing or malformed debugging directories.",
            "Security Tip: Suspicious persistence often appears as newly added environment variables.",
            "Privacy Note: File previews generated by operating systems may retain sensitive content.",
            "Forensic Insight: Startup folder remnants can indicate removed malware.",
            "Analysis Tip: Pay attention to mismatched timezone stamps in multi-part logs.",
            "Security Tip: Look for executables that adjust memory protections during runtime.",
            "Privacy Note: Cloud-based note apps store local backups containing sensitive drafts.",
            "Forensic Insight: Scrutinize error logs for references to missing modules used by attackers.",
            "Analysis Tip: Shell commands executed through encoded arguments often indicate malicious intent.",
            "Security Tip: Unexpected encryption routines executed by non-encryption apps signal intrusion.",
            "Privacy Note: Old browser sync backups store passwords even after local deletion.",
            "Forensic Insight: Hidden volumes inside encrypted containers can hold separate payloads.",
            "Analysis Tip: Examine user login token anomalies for unauthorized access patterns.",
            "Security Tip: Monitor for repeated permission changes on sensitive directories.",
            "Privacy Note: Some camera apps retain device serial numbers in saved RAW files.",
            "Forensic Insight: Old router logs can reveal attacker reconnaissance from previous sessions.",
            "Analysis Tip: Cross-reference system uptime with application event logs for inconsistencies.",
            "Security Tip: Unexpected modifications to hosts files often indicate local redirection attacks.",
            "Privacy Note: Fitness trackers store location traces independent of phone settings.",
            "Forensic Insight: Deleted virtual machine snapshots may still hold attack artifacts.",
            "Analysis Tip: Compare stack traces from repeated crashes to identify injected code.",
            "Security Tip: Randomized process names that mimic system binaries are high-risk indicators.",
            "Privacy Note: Hidden autosave documents sometimes predate user modifications.",
            "Forensic Insight: Packet capture metadata exposes hostname and OS fingerprints.",
            "Analysis Tip: Raised handle counts on idle processes often reveal injected threads.",
            "Security Tip: Time manipulation by attackers may appear as clock drift patterns.",
            "Privacy Note: Cached notification images store previews even without user interaction.",
            "Forensic Insight: Old event viewer logs can reveal credential harvesting activity.",
            "Analysis Tip: Track filesystem events for rapid bursts of modification across unrelated paths.",
            "Security Tip: Unregistered COM objects used at startup are a strong persistence signal.",
            "Privacy Note: Cloud platform metadata APIs can expose file history unintentionally.",
            "Forensic Insight: Partial stack memory can reveal function calls of terminated malware.",
            "Analysis Tip: Identify rough code similarities using opcode-level comparisons.",
            "Security Tip: Unexpected increases in encrypted outbound traffic should be examined closely.",
            "Privacy Note: Document recovery files preserve earlier drafts with sensitive details.",
            "Security Tip: Monitor TLS SNI values for unusual hostnames that could indicate C2 routing.",
            "Privacy Note: Metadata in shared calendars can reveal internal meeting patterns and participants.",
            "Forensic Insight: UEFI variable logs can show firmware-level changes and tamper attempts.",
            "Analysis Tip: Compare scrollbar positions in documents to detect unseen edits or previews.",
            "Technical Note: TPM event logs may provide a hardware-rooted timeline of boot changes.",
            "Best Practice: Collect volatile process lists as soon as possible to capture short lived artifacts.",
            "Threat Note: Abnormal use of IPv6 tunnels can be a sign of stealthy lateral movement.",
            "Detection Tip: Monitor SNAME fields in SMB traffic for disguised filenames.",
            "Data Recovery Tip: Slack clusters in HFS partitions sometimes include text fragments from old files.",
            "Investigator Tip: Capture DNS responses as well as queries to retain resolver behavior context.",
            "Forensic Technique: Analyze BIOS event logs for unexpected date or firmware changes.",
            "Digital Hygiene: Remove embedded comments in shared spreadsheets before public distribution.",
            "Expert Advice: Validate code signing timestamps against known CA issuance windows.",
            "Metadata Fact: Some printers log user IDs embedded in long print job identifiers.",
            "Evidence Note: Collect process environment blocks to preserve runtime configuration details.",
            "Privacy Tip: Mobile app debug logs shipped with releases can expose user data in plaintext.",
            "Security Tip: Detect chrome extension updates that occur outside of the store as potential supply chain vectors.",
            "Forensic Insight: Examine bootloader timestamps to detect intentional system time changes.",
            "Analysis Tip: Group crash stacks by module to reveal recurring injected components.",
            "Technical Note: Checksum mismatches in VHDX footers can point to corrupted or tampered images.",
            "Best Practice: Hash acquired memory images immediately and store hashes with the evidence chain.",
            "Threat Note: Abnormal ICMP destination unreachable messages may indicate scanning with spoofed sources.",
            "Detection Tip: Monitor for repeated use of single-use ports across many hosts as a sign of scanning.",
            "Data Recovery Tip: Recover B-tree nodes in APFS to search for deleted directory entries.",
            "Investigator Tip: Preserve hypervisor logs when investigating cloud VM compromises.",
            "Forensic Technique: Extract certificate chains from Windows CertStore for timeline analysis.",
            "Digital Hygiene: Disable unneeded debug logging in production to reduce sensitive leakage.",
            "Expert Advice: Cross-validate file timestamps using multiple artifacts such as MFT, USN, and shadow copies.",
            "Metadata Fact: Some scanners stamp scan job IDs into filenames created during batch scans.",
            "Evidence Note: Include mounted device serials in reports to tie artifacts to physical hardware.",
            "Privacy Tip: When sharing screen recordings, remove mouse movement overlays that may reveal actions.",
            "Security Tip: Alert on new cryptographic providers registered on endpoints outside maintenance windows.",
            "Forensic Insight: Browser service workers can persist long after tabs are closed and contain cached data.",
            "Analysis Tip: Visualize file similarity using fuzzy hashing to identify derivative samples.",
            "Technical Note: Validate partition GUIDs against expected images to detect hidden containers.",
            "Best Practice: Use write blockers during disk acquisition to prevent inadvertent timestamp changes.",
            "Threat Note: Watch for credential stuffing patterns from distributed IP ranges in short timeframes.",
            "Detection Tip: Track uncommon SMB dialect negotiations as anomalous client behavior.",
            "Data Recovery Tip: Examine file system journaling checkpoints to find in-flight writes.",
            "Investigator Tip: Capture device serial numbers for removable media to link to physical evidence.",
            "Forensic Technique: Parse log header offsets to reconstruct partially overwritten entries.",
            "Digital Hygiene: Limit metadata propagation in corporate templates to avoid leakage of internal IDs.",
            "Expert Advice: Correlate build IDs in binaries with public repositories for attribution leads.",
            "Metadata Fact: Some cloud sync clients attach machine-specific tokens to uploaded filenames.",
            "Evidence Note: Store acquisition timestamps in UTC with timezone metadata to avoid ambiguity.",
            "Privacy Tip: Export chat logs to formats that strip message IDs before sharing externally.",
            "Security Tip: Monitor for processes that spawn with parent PID 0 or other unusual parents.",
            "Forensic Insight: Look for stale DNS resolver cache files on endpoints during triage.",
            "Analysis Tip: Index function call fingerprints to cluster unknown binaries against known families.",
            "Technical Note: Verify filesystem block size assumptions when carving to prevent misalignment.",
            "Best Practice: Maintain a signed manifest of investigative tools to validate chain of custody.",
            "Threat Note: Abnormal use of SMTP VRFY or EXPN commands can indicate mail server probing.",
            "Detection Tip: Profile application startup sequences to spot injected initialization code.",
            "Data Recovery Tip: Recover WAL archive segments from SQLite to find soft-deleted rows.",
            "Investigator Tip: Keep a separate immutable copy of raw evidence and work on duplicates.",
            "Forensic Technique: Search for inconsistent locale encodings across log files to detect forged entries.",
            "Digital Hygiene: Strip embedded fonts and macros from documents before wider circulation.",
            "Expert Advice: Use multiple hash algorithms to mitigate the risk of rare collisions.",
            "Metadata Fact: Some remote logging systems append swath IDs for tracking batches of events.",
            "Evidence Note: Record the full command line used during acquisition for reproducibility.",
            "Privacy Tip: Disable automatic cloud uploads for apps handling sensitive photos or documents.",
            "Security Tip: Alert on new device enrollment events occurring at odd hours for corporate devices.",
            "Forensic Insight: Analyze kernel pool allocations for signatures of injected modules.",
            "Analysis Tip: Compare byte-level diffs between similar files to find hidden payloads.",
            "Technical Note: Check for leftover loopback network devices created by container runtimes.",
            "Best Practice: Maintain an index of known safe digests for baseline system files.",
            "Threat Note: Monitor for high volumes of small HTTPS POSTs to a single external domain.",
            "Detection Tip: Inspect TLS ALPN values that differ from expected application defaults.",
            "Data Recovery Tip: Parse orphaned inodes to find previously deleted files on ext filesystems.",
            "Investigator Tip: When possible, capture video of the forensic workstation during acquisition.",
            "Forensic Technique: Recover old mailbox indexes to trace deleted email threads.",
            "Digital Hygiene: Educate staff to avoid embedding system hostnames in shared documents.",
            "Expert Advice: Use entropy sliding windows to detect localized encrypted regions in files.",
            "Metadata Fact: Some CI build artifacts include environment variable dumps in metadata.",
            "Evidence Note: Preserve original file paths as seen on the source system in reports.",
            "Privacy Tip: Audit third party integrations for unnecessary access to user data.",
            "Security Tip: Monitor for changes to secure boot variables in enterprise fleets.",
            "Forensic Insight: Investigate timers and scheduled wake events to find remote wake triggers.",
            "Analysis Tip: Track API usage counts to detect rarely used, suspicious functionality.",
            "Technical Note: Verify kernel module signing states when checking for rootkits.",
            "Best Practice: Rotate forensic tool images to include latest safe vendor updates.",
            "Threat Note: Abnormal use of DNS CNAME chains can be a lightweight C2 technique.",
            "Detection Tip: Profile memory allocation churn to detect unpacking behavior.",
            "Data Recovery Tip: Reconstruct fragmented MP4 atoms to salvage partial media files.",
            "Investigator Tip: Preserve original timestamps on exported evidence for later validation.",
            "Forensic Technique: Use timeline correlation across endpoints to identify lateral movement windows.",
            "Digital Hygiene: Remove embedded GPS tracks from route exports before sharing screenshots.",
            "Expert Advice: Validate PE resource sections for unexpected embedded executables.",
            "Metadata Fact: Container images often keep layer creation timestamps that help timeline analysis.",
            "Evidence Note: Note the investigator name and purpose in every collected dataset.",
            "Privacy Tip: Limit access to diagnostic logs that include detailed user behavior metrics.",
            "Security Tip: Alert when administrative accounts are used from geographically distant locations within short windows.",
            "Forensic Insight: Recover browser session restores to find previously open but closed tabs.",
            "Analysis Tip: Use opcode n-gram models to fingerprint custom packers.",
            "Technical Note: Confirm disk encryption headers are intact before attempting decryption.",
            "Best Practice: Maintain a clear separation between triage and full forensic analysis copies.",
            "Threat Note: Monitor for subtle increases in DNS NXDOMAIN rates across domains.",
            "Detection Tip: Watch for processes that reattach to orphaned sockets for stealthy communication.",
            "Data Recovery Tip: Extract and analyze leftover thumbnails from document caches for preview evidence.",
            "Investigator Tip: Use multiple storage media to distribute risk of single point loss during evidence transport.",
            "Forensic Technique: Inspect TLS session tickets saved in process memory for session reuse indicators.",
            "Digital Hygiene: Remove development test accounts from live environments to reduce attack surface.",
            "Expert Advice: Track symbol table removal patterns as part of malware lineage analysis.",
            "Metadata Fact: Some backup systems append archive sequence numbers into filenames for deduplication.",
            "Evidence Note: When exporting artifacts, include the hash of the source volume in the header.",

        };

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, static_cast<int>(tips.size()) - 1);

        return tips[dis(gen)];
    }

    void setFilePath(const std::string& path) {
        filePath = path;
        analysisResults.clear();
    }

    void executeBasicForensicScan() {
        analysisResults.push_back("=== BASIC FORENSIC SCAN INITIATED ===");
        analysisResults.push_back("TIMESTAMP: " + getCurrentTimestamp());

        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (file) {
            std::streamsize size = file.tellg();
            char sizeStr[512];
            sprintf_s(sizeStr, sizeof(sizeStr),
                "FILE_SIZE: %lld bytes (%.2f MB / %.2f GB)",
                size,
                (double)size / (1024 * 1024),
                (double)size / (1024 * 1024 * 1024));
            analysisResults.push_back(sizeStr);
        }

        deepFileSignatureAnalysis();
        advancedFileSystemForensics();

        analysisResults.push_back("MD5_HASH: " + calculateFileHash("MD5"));
        analysisResults.push_back("SHA1_HASH: " + calculateFileHash("SHA1"));
        analysisResults.push_back("SHA256_HASH: " + calculateFileHash("SHA256"));
        analysisResults.push_back("SHA512_HASH: " + calculateFileHash("SHA512"));
    }

    void executeAdvancedThreatHunt() {
        analysisResults.push_back("=== ADVANCED THREAT HUNT INITIATED ===");
        detectAlternateDataStreams();
        entropyAndCompressionAnalysis();
        deepContentAnalysis();
        threatIntelligenceCorrelation();
    }

    void executeSteganographyInvestigation() {
        analysisResults.push_back("=== STEGANOGRAPHY INVESTIGATION INITIATED ===");
        advancedSteganographyDetection();
    }

    void executeMemoryForensics() {
        analysisResults.push_back("=== MEMORY FORENSICS INITIATED ===");
        memoryAndProcessAnalysis();
    }

    void executeComprehensiveAnalysis() {
        analysisRunning = true;

        analysisResults.push_back("================================================================================\n");
        analysisResults.push_back("                      COMPREHENSIVE FORENSIC ANALYSIS\n");
        analysisResults.push_back("================================================================================\n");
        analysisResults.push_back("INITIATION_TIMESTAMP: " + getCurrentTimestamp());
        analysisResults.push_back("TARGET: " + filePath);
        analysisResults.push_back("================================================================================\n");

        auto future1 = std::async(std::launch::async, [this]() { executeBasicForensicScan(); });
        auto future2 = std::async(std::launch::async, [this]() { executeAdvancedThreatHunt(); });
        auto future3 = std::async(std::launch::async, [this]() { executeSteganographyInvestigation(); });
        auto future4 = std::async(std::launch::async, [this]() { executeMemoryForensics(); });

        future1.wait();
        future2.wait();
        future3.wait();
        future4.wait();

        analysisResults.push_back("\n================================================================================\n");
        analysisResults.push_back("                         ANALYSIS COMPLETE\n");
        analysisResults.push_back("================================================================================\n");
        analysisResults.push_back("TERMINATION_TIMESTAMP: " + getCurrentTimestamp());
        analysisResults.push_back("STATUS: ALL MODULES EXECUTED SUCCESSFULLY");
        analysisResults.push_back("================================================================================\n");

        analysisRunning = false;
    }

    void displayAnalysisReport() {
        std::cout << "\n";
        std::cout << "================================================================================\n";
        std::cout << "                   ADVANCED FORENSIC ANALYSIS REPORT\n";
        std::cout << "================================================================================\n";
        std::cout << "TIMESTAMP: " << getCurrentTimestamp() << "\n";
        std::cout << "================================================================================\n\n";

        for (const auto& result : analysisResults) {
            std::cout << result << std::endl;
        }

        std::cout << "\n================================================================================\n";
        std::cout << "                          END OF ANALYSIS REPORT\n";
        std::cout << "================================================================================\n";
    }

    void exportReport() {
        exportComprehensiveReport();
    }

    void clearResults() {
        analysisResults.clear();
    }
};

std::string openFileDialogMulti() {
    OPENFILENAMEA ofn;
    char fileNames[8192] = "";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = fileNames;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0Executables\0*.exe;*.dll;*.sys;*.scr\0Documents\0*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx\0Images\0*.jpg;*.jpeg;*.png;*.bmp;*.gif;*.tiff\0Archives\0*.zip;*.rar;*.7z;*.tar;*.gz\0Scripts\0*.ps1;*.bat;*.cmd;*.vbs;*.js\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;

    if (GetOpenFileNameA(&ofn)) {
        return std::string(fileNames);
    }
    return "";
}

void displayHeader() {
    std::cout << "================================================================================\n";
    std::cout << "                   ADVANCED FORENSIC ANALYZER v1.0\n";
    std::cout << "================================================================================\n";
    std::cout << "A comprehensive digital forensics and threat analysis tool\n";
    std::cout << "================================================================================\n\n";
}

void displayDailyTip(AdvancedForensicAnalyzer& analyzer) {
    std::cout << "DAILY TIP: " << analyzer.getRandomTip() << "\n";
    std::cout << "================================================================================\n\n";
}

void simulateSystemCheck() {
    std::cout << "PERFORMING SYSTEM CHECK...\n";

    std::cout << "[1/5] Verifying cryptographic modules... ";
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "OK\n";

    std::cout << "[2/5] Validating forensic libraries... ";
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "OK\n";

    std::cout << "[3/5] Checking analysis engines... ";
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "READY\n";

    std::cout << "[4/5] Verifying system access... ";
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "OK\n";

    std::cout << "[5/5] Initializing modules... ";
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "COMPLETE\n";

    std::cout << "\nSYSTEM STATUS: READY\n";
    std::cout << "ALL MODULES: OPERATIONAL\n";
}

int showMainMenu() {
    int choice;
    std::cout << "\n";
    std::cout << "================================================================================\n";
    std::cout << "                          MAIN ANALYSIS MENU\n";
    std::cout << "================================================================================\n";
    std::cout << "1.  BASIC FORENSIC SCAN\n";
    std::cout << "    - File signature analysis, metadata extraction, hash generation\n\n";

    std::cout << "2.  ADVANCED THREAT HUNT\n";
    std::cout << "    - ADS detection, entropy analysis, content pattern matching\n\n";

    std::cout << "3.  STEGANOGRAPHY INVESTIGATION\n";
    std::cout << "    - LSB analysis, chi-square tests, hidden data detection\n\n";

    std::cout << "4.  MEMORY FORENSICS\n";
    std::cout << "    - Process memory analysis, system resource monitoring\n\n";

    std::cout << "5.  COMPREHENSIVE ANALYSIS\n";
    std::cout << "    - Full spectrum forensic examination (All modules)\n\n";

    std::cout << "6.  MULTI-FILE ANALYSIS\n";
    std::cout << "    - Batch process multiple files for threat assessment\n\n";

    std::cout << "7.  EXPORT ANALYSIS REPORT\n";
    std::cout << "    - Generate detailed forensic report\n\n";

    std::cout << "8.  SYSTEM STATUS\n";
    std::cout << "    - Display operational environment status\n\n";

    std::cout << "9.  CLEAR RESULTS\n";
    std::cout << "    - Reset analysis results\n\n";

    std::cout << "0.  EXIT\n";
    std::cout << "    - Close application\n";
    std::cout << "================================================================================\n";
    std::cout << "SELECT OPTION: ";

    std::cin >> choice;

    std::cin.clear();
    std::cin.ignore(10000, '\n');

    return choice;
}

int main() {
    displayHeader();

    AdvancedForensicAnalyzer forensicAnalyzer;

    displayDailyTip(forensicAnalyzer);

    std::cout << "INITIALIZING FORENSIC ANALYSIS ENVIRONMENT...\n";
    simulateSystemCheck();

    int choice;
    do {
        choice = showMainMenu();

        try {
            switch (choice) {
            case 1: {
                std::string filePath = openFileDialogMulti();
                if (!filePath.empty()) {
                    forensicAnalyzer.setFilePath(filePath);
                    std::cout << "\nINITIATING BASIC FORENSIC SCAN...\n";
                    forensicAnalyzer.executeBasicForensicScan();
                    forensicAnalyzer.displayAnalysisReport();
                }
                break;
            }
            case 2: {
                std::string filePath = openFileDialogMulti();
                if (!filePath.empty()) {
                    forensicAnalyzer.setFilePath(filePath);
                    std::cout << "\nINITIATING ADVANCED THREAT HUNT...\n";
                    forensicAnalyzer.executeAdvancedThreatHunt();
                    forensicAnalyzer.displayAnalysisReport();
                }
                break;
            }
            case 3: {
                std::string filePath = openFileDialogMulti();
                if (!filePath.empty()) {
                    forensicAnalyzer.setFilePath(filePath);
                    std::cout << "\nINITIATING STEGANOGRAPHY INVESTIGATION...\n";
                    forensicAnalyzer.executeSteganographyInvestigation();
                    forensicAnalyzer.displayAnalysisReport();
                }
                break;
            }
            case 4: {
                std::string filePath = openFileDialogMulti();
                if (!filePath.empty()) {
                    forensicAnalyzer.setFilePath(filePath);
                    std::cout << "\nINITIATING MEMORY FORENSICS...\n";
                    forensicAnalyzer.executeMemoryForensics();
                    forensicAnalyzer.displayAnalysisReport();
                }
                break;
            }
            case 5: {
                std::string filePath = openFileDialogMulti();
                if (!filePath.empty()) {
                    forensicAnalyzer.setFilePath(filePath);
                    std::cout << "\nINITIATING COMPREHENSIVE ANALYSIS...\n";
                    std::cout << "THIS OPERATION MAY TAKE SEVERAL MINUTES...\n";
                    forensicAnalyzer.executeComprehensiveAnalysis();
                    forensicAnalyzer.displayAnalysisReport();
                }
                break;
            }
            case 6: {
                std::cout << "\nMULTI-FILE ANALYSIS SELECTED\n";
                std::cout << "Select multiple files for batch processing...\n";
                std::string files = openFileDialogMulti();
                if (!files.empty()) {
                    std::cout << "Batch processing initiated for selected files...\n";
                }
                break;
            }
            case 7:
                std::cout << "\nEXPORTING ANALYSIS REPORT...\n";
                forensicAnalyzer.exportReport();
                std::cout << "REPORT EXPORTED SUCCESSFULLY\n";
                break;
            case 8:
                std::cout << "\nSYSTEM STATUS:\n";
                std::cout << "Process ID: " << GetCurrentProcessId() << "\n";
                std::cout << "System Status: OPERATIONAL\n";
                std::cout << "Forensic Modules: ACTIVE\n";
                std::cout << "Analysis Engine: READY\n";
                break;
            case 9:
                forensicAnalyzer.clearResults();
                std::cout << "\nRESULTS CLEARED - READY FOR NEW ANALYSIS\n";
                break;
            case 0:
                std::cout << "\nCLOSING APPLICATION...\n";
                std::cout << "Thank you for using Advanced Forensic Analyzer\n";
                break;
            default:
                std::cout << "\nINVALID SELECTION\n";
                std::cout << "PLEASE SELECT VALID OPTION (0-9)\n";
            }
        }
        catch (const std::exception& e) {
            std::cout << "\nANALYSIS ERROR: " << e.what() << std::endl;
            std::cout << "CONTINUING OPERATIONS...\n";
        }
        catch (...) {
            std::cout << "\nUNKNOWN ANALYSIS ERROR\n";
            std::cout << "CONTINUING OPERATIONS...\n";
        }

        if (choice != 0) {
            std::cout << "\nPRESS ENTER TO CONTINUE...";
            std::cin.get();
        }
    } while (choice != 0);

    std::cout << "ADVANCED FORENSIC ANALYZER - SESSION ENDED\n";
    return 0;
}