# Meta Forensics

Advanced digital forensics open source tool for comprehensive file analysis, metadata extraction, and advanced threat detection. Professional-grade security analysis platform built for cybersecurity professionals, digital forensics investigators, and security researchers.

## Features

### Core Analysis Capabilities
- **Deep File Signature Analysis** - Identifies 100+ file formats through header analysis and magic number detection
- **Comprehensive Metadata Extraction** - EXIF data, NTFS attributes, creation/modification/access timestamps, file system metadata
- **Advanced Threat Detection** - Malware pattern recognition, suspicious content scanning, behavioral analysis
- **Steganography Detection** - LSB (Least Significant Bit) analysis, chi-square statistical tests, hidden data identification
- **Alternate Data Streams (ADS) Detection** - NTFS hidden stream analysis for Windows systems
- **Entropy Analysis** - Encryption and compression detection through mathematical randomness analysis
- **Memory Forensics** - Process memory analysis, system resource monitoring, runtime behavior assessment

### Advanced Security Features
- **Hash Generation** - MD5, SHA1, SHA256, SHA512 cryptographic hashing for file integrity verification
- **Network Artifact Scanning** - URL, IP address, email pattern detection in file contents
- **Timeline Analysis** - File creation timeline reconstruction and timestamp anomaly detection
- **Content Pattern Matching** - Regular expression-based pattern recognition for sensitive data
- **Multi-threaded Processing** - Parallel analysis engines for fast comprehensive scanning
- **Professional Reporting** - Detailed forensic reports with risk assessment and confidence levels

## Installation & Build

### Prerequisites
- **Operating System**: Windows 10/11 (64-bit recommended)
- **Compiler**: Visual Studio 2019 or later with C++ support
- **Libraries**: Windows SDK, CryptoAPI, Win32 API

### Build Instructions
# Method 1: Using build script (Recommended)
build.bat

# Method 2: Manual compilation
cl /EHsc /O2 /DUNICODE /D_UNICODE main.cpp advapi32.lib shell32.lib psapi.lib urlmon.lib

### Verification
After successful build, run:
MetaForensics.exe
The application should display the main menu interface.

## Usage Guide

### Basic Operation
1. Launch Application: Execute MetaForensics.exe
2. File Selection: Use the Windows file dialog to select target file
3. Analysis Selection: Choose from available analysis modules
4. Results Review: Examine comprehensive forensic report
5. Export Options: Save detailed analysis reports

### Analysis Modules
1. Basic Forensic Scan
   - File size analysis and storage calculations
   - File signature identification and format verification
   - Basic metadata extraction (timestamps, attributes)
   - Multi-algorithm hash generation (MD5, SHA1, SHA256, SHA512)
   - File type categorization and risk assessment

2. Advanced Threat Hunt
   - Alternate Data Streams (ADS) detection and analysis
   - Entropy analysis for encryption/compression detection
   - Content pattern matching for suspicious strings
   - Threat intelligence correlation with known malware patterns
   - Behavioral analysis and anomaly detection

3. Steganography Investigation
   - LSB (Least Significant Bit) pattern analysis
   - Chi-square statistical testing for hidden data
   - Entropy-based steganography detection
   - Confidence level assessment for hidden content
   - Advanced statistical anomaly detection

4. Memory Forensics
   - Process memory usage analysis
   - System resource monitoring and profiling
   - Memory footprint assessment
   - Performance impact analysis
   - Runtime behavior tracking

5. Comprehensive Analysis
   - Full multi-threaded execution of all analysis modules
   - Cross-correlation of findings between different analysis types
   - Comprehensive risk assessment scoring
   - Detailed timeline reconstruction
   - Professional forensic reporting

## Supported File Types

### Executables & System Files
.exe - Windows Executables
.dll - Dynamic Link Libraries
.sys - System Drivers
.scr - Screen Savers
.msi - Windows Installers

### Documents & Office Files
.pdf - Portable Document Format
.doc, .docx - Microsoft Word Documents
.xls, .xlsx - Microsoft Excel Spreadsheets
.ppt, .pptx - Microsoft PowerPoint Presentations
.rtf - Rich Text Format

### Images & Media
.jpg, .jpeg - JPEG Images
.png - Portable Network Graphics
.bmp - Bitmap Images
.gif - Graphics Interchange Format
.tiff, .tif - Tagged Image File Format

### Archives & Compressed Files
.zip - ZIP Archives
.rar - RAR Archives
.7z - 7-Zip Archives
.tar - Tape Archives
.gz - GZIP Compressed Files

### Scripts & Source Code
.ps1 - PowerShell Scripts
.bat - Batch Files
.cmd - Command Scripts
.vbs - VBScript Files
.js - JavaScript Files

## Technical Specifications

### Architecture
- Programming Language: C++ 17
- Platform: Windows Native (Win32 API)
- Architecture: Multi-threaded, modular design
- Dependencies: Windows CryptoAPI, Win32 Libraries

### Analysis Engines
- Signature Analysis: 100+ file format signatures
- Metadata Extraction: EXIF, NTFS, FAT32, timestamps
- Cryptographic Hashing: MD5, SHA1, SHA256, SHA512
- Pattern Matching: Regular expression engine
- Statistical Analysis: Entropy calculations, chi-square tests

### Performance
- Processing Speed: Multi-threaded parallel analysis
- Memory Usage: Optimized memory management
- File Size Support: Up to 4GB+ files
- Analysis Depth: Comprehensive multi-layer scanning

## Legal & Ethical Usage

### Intended Use Cases
- Digital forensics investigations
- Cybersecurity threat analysis
- Incident response and analysis
- Security research and education
- File integrity verification
- Malware analysis and detection

### Legal Compliance
- Authorization Required: Always obtain proper legal authorization
- Privacy Compliance: Respect data privacy laws and regulations
- Evidence Handling: Follow proper chain of custody procedures
- Reporting Requirements: Maintain accurate documentation and reporting

### Ethical Guidelines
- Use only for legitimate security purposes
- Respect intellectual property rights
- Maintain confidentiality of sensitive information
- Report vulnerabilities responsibly
- Contribute to security community knowledge

## Troubleshooting

### Common Issues

#### Build Failures
- Missing Compiler: Ensure Visual Studio C++ compiler is installed
- Library Errors: Verify Windows SDK and necessary libraries are available
- Permission Issues: Run command prompt as Administrator if needed

#### Runtime Errors
- File Access Denied: Check file permissions and anti-virus software
- Memory Issues: Ensure sufficient system resources are available
- Analysis Failures: Verify file integrity and format compatibility

#### Performance Optimization
- Close unnecessary applications during analysis
- Ensure adequate free memory availability
- Use SSD storage for faster file access
- Monitor system resources during comprehensive scans

## Contributing
We welcome contributions from the security community:

### How to Contribute
- Fork the repository
- Create feature branches
- Submit pull requests with detailed descriptions
- Follow code style guidelines
- Include appropriate documentation

### Areas for Contribution
- New file format signatures
- Enhanced analysis algorithms
- Additional platform support
- Performance optimizations
- Documentation improvements

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Support

### Documentation
- Full technical documentation available in source code
- In-tool help system and guidance
- Example analysis reports and use cases

### Community
- GitHub Issues for bug reports and feature requests
- Security community forums and discussions
- Professional cybersecurity networks

### Professional Use
For enterprise or professional use, ensure proper training and certification in digital forensics procedures.

Disclaimer: This tool is intended for legitimate forensic analysis, cybersecurity research, and educational purposes only. Users are solely responsible for ensuring compliance with all applicable laws and regulations. Always obtain proper authorization before conducting any form of digital analysis or investigation.
