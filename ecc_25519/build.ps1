# PowerShell Build Script for Curve25519 ECC Implementation
# Usage: .\build.ps1 [clean|all|test]

param(
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

function Build-Object {
    param([string]$Source)
    
    $Object = $Source -replace "\.c$", ".o"
    Write-Host "Compiling $Source..." -ForegroundColor Green
    gcc -Wall -Wextra -O2 -c $Source -o $Object
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to compile $Source"
    }
}

function Build-Executable {
    param([string]$Name, [string[]]$Objects)
    
    Write-Host "Linking $Name.exe..." -ForegroundColor Blue
    gcc -Wall -Wextra -O2 -o "$Name.exe" @Objects
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to link $Name.exe"
    }
}

function Clean-Build {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item -Force -ErrorAction SilentlyContinue "*.o", "*.exe"
    Write-Host "Clean complete." -ForegroundColor Green
}

function Build-All {
    Write-Host "Building Curve25519 ECC Implementation..." -ForegroundColor Cyan
    
    # Compile source files
    Build-Object "curve25519.c"
    Build-Object "common.c"
    Build-Object "ecc_main.c"
    Build-Object "keygen.c"
    
    # Link executables
    Build-Executable "ecc_main" @("curve25519.o", "common.o", "ecc_main.o")
    Build-Executable "keygen" @("curve25519.o", "common.o", "keygen.o")
    
    Write-Host "`nBuild complete! Generated executables:" -ForegroundColor Green
    Write-Host "  - ecc_main.exe    (encrypt/decrypt files)" -ForegroundColor White
    Write-Host "  - keygen.exe      (generate key pairs)" -ForegroundColor White
}

function Run-Tests {
    Write-Host "Running comprehensive tests..." -ForegroundColor Cyan
    Write-Host "No comprehensive test suite available yet." -ForegroundColor Yellow
    Write-Host "You can manually test with:" -ForegroundColor White
    Write-Host "  .\keygen.exe test" -ForegroundColor Gray
    Write-Host "  .\ecc_main.exe -e -i input.txt -k test -o output.enc" -ForegroundColor Gray
    Write-Host "  .\ecc_main.exe -d -i output.enc -k test -o decrypted.txt" -ForegroundColor Gray
}

function Show-Usage {
    Write-Host "`nCurve25519 ECC Build Script" -ForegroundColor Cyan
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
}

# Main execution
try {
    switch ($Target.ToLower()) {
        "all" { Build-All }
        "clean" { Clean-Build }
        "test" { Run-Tests }
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
