# PowerShell Build Script for AES (Advanced Encryption Standard) Implementation
# Usage: .\build.ps1 [clean|all|test]

param(
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

function Build-Object {
    param([string]$Source)
    
    $Object = $Source -replace "\.c$", ".o"
    Write-Host "Compiling $Source..." -ForegroundColor Green
    gcc -Wall -Wextra -O2 -std=c99 -c $Source -o $Object
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to compile $Source"
    }
}

function Build-Executable {
    param([string]$Name, [string[]]$Objects)
    
    Write-Host "Linking $Name.exe..." -ForegroundColor Blue
    gcc -Wall -Wextra -O2 -std=c99 -o "$Name.exe" @Objects
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to link $Name.exe"
    }
}

function Clear-Build {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item -Force -ErrorAction SilentlyContinue "*.o", "*.exe"
    Write-Host "Clean complete." -ForegroundColor Green
}

function Build-All {
    Write-Host "Building AES (Advanced Encryption Standard) Implementation..." -ForegroundColor Cyan
    
    # Compile core source files
    Build-Object "aes.c"
    Build-Object "common.c"
    
    # Compile driver files
    Build-Object "driver_aes_CBC.c"
    Build-Object "driver_aes_ECB.c"
    
    # Link executables
    Build-Executable "aes_cbc" @("aes.o", "common.o", "driver_aes_CBC.o")
    Build-Executable "aes_ecb" @("aes.o", "common.o", "driver_aes_ECB.o")
    
    Write-Host "`nBuild complete! Generated executables:" -ForegroundColor Green
    Write-Host "  - aes_cbc.exe     (AES CBC mode - recommended for security)" -ForegroundColor White
    Write-Host "  - aes_ecb.exe     (AES ECB mode - for demonstration only)" -ForegroundColor White
    Write-Host "`nNote: CBC mode is cryptographically secure, ECB mode is NOT secure for real data!" -ForegroundColor Yellow
}

function Show-Tests {
    Write-Host "Manual testing instructions for AES:" -ForegroundColor Cyan
    Write-Host "`n1. Create key files (different key sizes):" -ForegroundColor White
    Write-Host "   # AES-128 (16-byte key)" -ForegroundColor Gray
    Write-Host "   echo 'MySecretKey12345' > key128.txt" -ForegroundColor Gray
    Write-Host "   # AES-192 (24-byte key)" -ForegroundColor Gray
    Write-Host "   echo 'MySecretKey123456789012' > key192.txt" -ForegroundColor Gray
    Write-Host "   # AES-256 (32-byte key)" -ForegroundColor Gray
    Write-Host "   echo 'MySecretKey12345678901234567890' > key256.txt" -ForegroundColor Gray
    
    Write-Host "`n2. Create test input:" -ForegroundColor White
    Write-Host "   echo 'Hello AES encryption! This is a test message.' > input.txt" -ForegroundColor Gray
    
    Write-Host "`n3. Test CBC mode (RECOMMENDED - secure):" -ForegroundColor White
    Write-Host "   .\aes_cbc.exe -e -i input.txt -k key128.txt -o encrypted_cbc.bin" -ForegroundColor Gray
    Write-Host "   .\aes_cbc.exe -d -i encrypted_cbc.bin -k key128.txt -o decrypted_cbc.txt" -ForegroundColor Gray
    
    Write-Host "`n4. Test ECB mode (DEMONSTRATION ONLY - not secure):" -ForegroundColor White
    Write-Host "   .\aes_ecb.exe -e -i input.txt -k key128.txt -o encrypted_ecb.bin" -ForegroundColor Gray
    Write-Host "   .\aes_ecb.exe -d -i encrypted_ecb.bin -k key128.txt -o decrypted_ecb.txt" -ForegroundColor Gray
    
    Write-Host "`n5. Verify results:" -ForegroundColor White
    Write-Host "   Get-Content input.txt" -ForegroundColor Gray
    Write-Host "   Get-Content decrypted_cbc.txt" -ForegroundColor Gray
    Write-Host "   Get-Content decrypted_ecb.txt" -ForegroundColor Gray
    
    Write-Host "`n6. Test different key sizes:" -ForegroundColor White
    Write-Host "   .\aes_cbc.exe -e -i input.txt -k key192.txt -o encrypted_192.bin" -ForegroundColor Gray
    Write-Host "   .\aes_cbc.exe -e -i input.txt -k key256.txt -o encrypted_256.bin" -ForegroundColor Gray
    
    Write-Host "`nSecurity Notes:" -ForegroundColor Yellow
    Write-Host "  - CBC mode uses random IV and is cryptographically secure" -ForegroundColor White
    Write-Host "  - ECB mode is deterministic and reveals patterns in data" -ForegroundColor White
    Write-Host "  - Always use CBC mode for real applications" -ForegroundColor White
    Write-Host "  - AES-128 is sufficient for most applications" -ForegroundColor White
    Write-Host "  - AES-256 provides additional security margin" -ForegroundColor White
}

function Show-Usage {
    Write-Host "`nAES (Advanced Encryption Standard) Build Script" -ForegroundColor Cyan
    Write-Host "Usage: .\build.ps1 [command]" -ForegroundColor White
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  all     - Build all executables (default)" -ForegroundColor White
    Write-Host "  clean   - Clean build artifacts" -ForegroundColor White
    Write-Host "  test    - Show manual testing instructions" -ForegroundColor White
    Write-Host "  help    - Show this help message" -ForegroundColor White
    Write-Host "`nExamples:" -ForegroundColor Yellow
    Write-Host "  .\build.ps1                # Build everything" -ForegroundColor White
    Write-Host "  .\build.ps1 clean          # Clean build files" -ForegroundColor White
    Write-Host "  .\build.ps1 test           # Show test instructions" -ForegroundColor White
    Write-Host "`nAbout AES:" -ForegroundColor Yellow
    Write-Host "  AES (Advanced Encryption Standard) is the current standard for" -ForegroundColor White
    Write-Host "  symmetric encryption, adopted by the U.S. government and used" -ForegroundColor White
    Write-Host "  worldwide. This implementation supports:" -ForegroundColor White
    Write-Host "  - AES-128, AES-192, and AES-256 key sizes" -ForegroundColor White
    Write-Host "  - CBC mode with random IV (secure)" -ForegroundColor White
    Write-Host "  - ECB mode (for educational purposes only)" -ForegroundColor White
    Write-Host "  - PKCS#7 padding for arbitrary data lengths" -ForegroundColor White
}

# Main execution
try {
    switch ($Target.ToLower()) {
        "all" { Build-All }
        "clean" { Clear-Build }
        "test" { Show-Tests }
        "help" { Show-Usage }
        default { 
            Write-Host "Unknown target: $Target" -ForegroundColor Red
            Show-Usage
            exit 1
        }
    }
} catch {
    Write-Host "Build failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
