# PowerShell Build Script for TEA (Tiny Encryption Algorithm) Implementation
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
    Write-Host "Building TEA (Tiny Encryption Algorithm) Implementation..." -ForegroundColor Cyan
    
    # Compile source files
    Build-Object "tea.c"
    Build-Object "common.c"
    Build-Object "tea_main.c"
    
    # Link executable
    Build-Executable "tea_cbc" @("tea.o", "common.o", "tea_main.o")
    
    Write-Host "`nBuild complete! Generated executable:" -ForegroundColor Green
    Write-Host "  - tea_cbc.exe     (TEA CBC mode encrypt/decrypt)" -ForegroundColor White
}

function Show-Tests {
    Write-Host "Manual testing instructions for TEA:" -ForegroundColor Cyan
    Write-Host "1. Create a key file:" -ForegroundColor White
    Write-Host "   echo 'MySecretKey12345' > key.txt" -ForegroundColor Gray
    Write-Host "2. Create test input:" -ForegroundColor White
    Write-Host "   echo 'Hello TEA encryption!' > input.txt" -ForegroundColor Gray
    Write-Host "3. Encrypt:" -ForegroundColor White
    Write-Host "   .\tea_cbc.exe -e -i input.txt -k key.txt -o encrypted.bin" -ForegroundColor Gray
    Write-Host "4. Decrypt:" -ForegroundColor White
    Write-Host "   .\tea_cbc.exe -d -i encrypted.bin -k key.txt -o decrypted.txt" -ForegroundColor Gray
    Write-Host "5. Verify:" -ForegroundColor White
    Write-Host "   Get-Content decrypted.txt" -ForegroundColor Gray
}

function Show-Usage {
    Write-Host "`nTEA (Tiny Encryption Algorithm) Build Script" -ForegroundColor Cyan
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
    Write-Host "`nAbout TEA:" -ForegroundColor Yellow
    Write-Host "  TEA (Tiny Encryption Algorithm) is a block cipher designed for" -ForegroundColor White
    Write-Host "  simplicity and efficiency. This implementation uses CBC mode" -ForegroundColor White
    Write-Host "  with PKCS#7 padding for secure encryption of arbitrary data." -ForegroundColor White
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
