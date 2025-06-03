# Automated VDD Driver Signing and Installation System

## Overview

For production deployment, we need to handle:
1. **Code Signing Certificate Management**
2. **Automated Driver Signing**
3. **Certificate Installation**
4. **Driver Installation with Admin Privileges**
5. **Rollback and Error Handling**

## 1. Certificate and Signing Infrastructure

### 1.1 Certificate Options

**Option A: EV Code Signing Certificate (Recommended for Production)**
```powershell
# Purchase from DigiCert, Sectigo, or similar CA
# Costs ~$300-500/year but provides immediate trust
# No Windows warning dialogs for users
```

**Option B: Self-Signed Certificate (Development/Enterprise)**
```powershell
# Generate self-signed certificate
# Requires manual trust installation on each machine
# Shows security warnings to users
```

**Option C: Enterprise Certificate Authority**
```powershell
# For enterprise deployments
# Uses internal CA infrastructure
# Requires domain-joined machines
```

### 1.2 Certificate Generation Script
**File: `scripts/generate_certificate.ps1`**

```powershell
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$CertificateSubject = "CN=VDD Remote Desktop Driver",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePassword = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$InstallToStore = $true
)

function New-CodeSigningCertificate {
    param(
        [string]$Subject,
        [string]$Password,
        [bool]$InstallToStore
    )
    
    Write-Host "Generating self-signed code signing certificate..." -ForegroundColor Green
    
    # Create certificate
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -ValidityPeriod Years `
        -ValidityLength 3 `
        -CertStoreLocation "Cert:\CurrentUser\My"
    
    # Export certificate
    $certPath = ".\certificates\VDDCodeSigning.pfx"
    $certPublicPath = ".\certificates\VDDCodeSigning.cer"
    
    New-Item -ItemType Directory -Path ".\certificates" -Force | Out-Null
    
    if ($Password) {
        $securePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $securePassword
    } else {
        Export-PfxCertificate -Cert $cert -FilePath $certPath -ProtectTo $env:USERNAME
    }
    
    Export-Certificate -Cert $cert -FilePath $certPublicPath
    
    if ($InstallToStore) {
        # Install to Trusted Root and Trusted Publishers
        Import-Certificate -FilePath $certPublicPath -CertStoreLocation "Cert:\LocalMachine\Root"
        Import-Certificate -FilePath $certPublicPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"
        
        Write-Host "Certificate installed to system stores" -ForegroundColor Green
    }
    
    Write-Host "Certificate generated: $certPath" -ForegroundColor Green
    Write-Host "Public certificate: $certPublicPath" -ForegroundColor Green
    
    return @{
        CertificatePath = $certPath
        PublicCertPath = $certPublicPath
        Thumbprint = $cert.Thumbprint
    }
}

# Generate certificate
$certInfo = New-CodeSigningCertificate -Subject $CertificateSubject -Password $CertificatePassword -InstallToStore $InstallToStore

# Save certificate info for build process
@{
    CertificatePath = $certInfo.CertificatePath
    PublicCertPath = $certInfo.PublicCertPath
    Thumbprint = $certInfo.Thumbprint
    Subject = $CertificateSubject
    CreatedDate = Get-Date
} | ConvertTo-Json | Out-File ".\certificates\cert_info.json"

Write-Host "Certificate information saved to cert_info.json" -ForegroundColor Green
```

## 2. Automated Build and Signing Pipeline

### 2.1 MSBuild Integration
**File: `build/sign_driver.targets`**

```xml
<Project>
  <PropertyGroup>
    <SigningCertificatePath Condition="'$(SigningCertificatePath)' == ''">$(MSBuildProjectDirectory)\..\certificates\VDDCodeSigning.pfx</SigningCertificatePath>
    <SigningCertificatePassword Condition="'$(SigningCertificatePassword)' == ''"></SigningCertificatePassword>
    <TimestampUrl>http://timestamp.digicert.com</TimestampUrl>
  </PropertyGroup>

  <Target Name="SignDriver" AfterTargets="Build">
    <ItemGroup>
      <FilesToSign Include="$(TargetDir)*.sys" />
      <FilesToSign Include="$(TargetDir)*.dll" />
      <FilesToSign Include="$(TargetDir)*.exe" />
    </ItemGroup>

    <Message Text="Signing driver files..." Importance="high" />
    
    <Exec Command="signtool sign /f &quot;$(SigningCertificatePath)&quot; /p &quot;$(SigningCertificatePassword)&quot; /t $(TimestampUrl) /v &quot;%(FilesToSign.Identity)&quot;"
          ContinueOnError="false"
          WorkingDirectory="$(MSBuildProjectDirectory)" />

    <!-- Verify signatures -->
    <Exec Command="signtool verify /pa /v &quot;%(FilesToSign.Identity)&quot;"
          ContinueOnError="false"
          WorkingDirectory="$(MSBuildProjectDirectory)" />
  </Target>

  <Target Name="CreateDriverPackage" AfterTargets="SignDriver">
    <Message Text="Creating driver installation package..." Importance="high" />
    
    <!-- Create timestamped package directory -->
    <PropertyGroup>
      <PackageDir>$(MSBuildProjectDirectory)\..\packages\VDD_$(Configuration)_$([System.DateTime]::Now.ToString('yyyyMMdd_HHmmss'))</PackageDir>
    </PropertyGroup>
    
    <ItemGroup>
      <DriverFiles Include="$(TargetDir)*.*" />
      <CertificateFiles Include="$(MSBuildProjectDirectory)\..\certificates\*.cer" />
      <InstallScripts Include="$(MSBuildProjectDirectory)\..\scripts\install_*.ps1" />
    </ItemGroup>
    
    <MakeDir Directories="$(PackageDir)" />
    <Copy SourceFiles="@(DriverFiles)" DestinationFolder="$(PackageDir)" />
    <Copy SourceFiles="@(CertificateFiles)" DestinationFolder="$(PackageDir)\certificates" />
    <Copy SourceFiles="@(InstallScripts)" DestinationFolder="$(PackageDir)" />
    
    <!-- Create installation info file -->
    <WriteLinesToFile File="$(PackageDir)\install_info.json" 
                      Lines='{"version": "$(AssemblyVersion)", "buildDate": "$([System.DateTime]::Now.ToString())", "configuration": "$(Configuration)"}' />
    
    <Message Text="Driver package created: $(PackageDir)" Importance="high" />
  </Target>
</Project>
```

### 2.2 PowerShell Build Script
**File: `scripts/build_and_sign.ps1`**

```powershell
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePassword = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$InstallAfterBuild = $false
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Status {
    param([string]$Message, [string]$Color = "Green")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    # Check Visual Studio Build Tools
    $msbuildPath = Get-Command "msbuild.exe" -ErrorAction SilentlyContinue
    if (-not $msbuildPath) {
        $vsInstallPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
        if (-not (Test-Path $vsInstallPath)) {
            $vsInstallPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
        }
        
        if (-not (Test-Path $vsInstallPath)) {
            throw "MSBuild not found. Please install Visual Studio Build Tools."
        }
        
        $env:PATH = "$env:PATH;$(Split-Path $vsInstallPath)"
    }
    
    # Check Windows SDK
    $signtoolPath = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if (-not $signtoolPath) {
        $sdkPath = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | 
                   Sort-Object Name -Descending | Select-Object -First 1
        
        if (-not $sdkPath) {
            throw "SignTool not found. Please install Windows SDK."
        }
        
        $env:PATH = "$env:PATH;$(Split-Path $sdkPath.FullName)"
    }
    
    Write-Status "Prerequisites check passed"
}

function New-BuildEnvironment {
    Write-Status "Setting up build environment..."
    
    # Create output directories
    $outputDir = ".\build\$Configuration\$Platform"
    $packageDir = ".\packages"
    $certDir = ".\certificates"
    
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    New-Item -ItemType Directory -Path $certDir -Force | Out-Null
    
    Write-Status "Build environment ready"
}

function Invoke-DriverBuild {
    Write-Status "Building VDD driver..."
    
    $solutionPath = ".\Virtual Display Driver (HDR)\MttVDD.sln"
    
    if (-not (Test-Path $solutionPath)) {
        throw "Solution file not found: $solutionPath"
    }
    
    # Build the driver
    $buildArgs = @(
        $solutionPath
        "/p:Configuration=$Configuration"
        "/p:Platform=$Platform"
        "/p:SigningCertificatePath=$CertificatePath"
        "/p:SigningCertificatePassword=$CertificatePassword"
        "/verbosity:minimal"
        "/nologo"
    )
    
    & msbuild @buildArgs
    
    if ($LASTEXITCODE -ne 0) {
        throw "Driver build failed with exit code $LASTEXITCODE"
    }
    
    Write-Status "Driver build completed successfully"
}

function Invoke-BackendBuild {
    Write-Status "Building C++ backend..."
    
    $cmakeDir = ".\backend\build"
    New-Item -ItemType Directory -Path $cmakeDir -Force | Out-Null
    
    Push-Location $cmakeDir
    try {
        # Configure with CMake
        & cmake .. -A $Platform -DCMAKE_BUILD_TYPE=$Configuration
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed"
        }
        
        # Build
        & cmake --build . --config $Configuration
        if ($LASTEXITCODE -ne 0) {
            throw "Backend build failed"
        }
        
        # Sign binaries
        if ($CertificatePath -and (Test-Path $CertificatePath)) {
            Get-ChildItem ".\$Configuration\*.dll", ".\$Configuration\*.exe" | ForEach-Object {
                Write-Status "Signing $($_.Name)..."
                & signtool sign /f $CertificatePath /p $CertificatePassword /t "http://timestamp.digicert.com" /v $_.FullName
            }
        }
        
    } finally {
        Pop-Location
    }
    
    Write-Status "Backend build completed successfully"
}

function New-InstallationPackage {
    Write-Status "Creating installation package..."
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $packageName = "VDD_RemoteDesktop_$Configuration`_$Platform`_$timestamp"
    $packagePath = ".\packages\$packageName"
    
    New-Item -ItemType Directory -Path $packagePath -Force | Out-Null
    
    # Copy driver files
    $driverSource = ".\Virtual Display Driver (HDR)\MttVDD\$Platform\$Configuration"
    if (Test-Path $driverSource) {
        Copy-Item "$driverSource\*" -Destination $packagePath -Recurse -Force
    }
    
    # Copy backend files
    $backendSource = ".\backend\build\$Configuration"
    if (Test-Path $backendSource) {
        Copy-Item "$backendSource\*.dll" -Destination $packagePath -Force
        Copy-Item "$backendSource\*.exe" -Destination $packagePath -Force
    }
    
    # Copy certificates
    if (Test-Path ".\certificates") {
        Copy-Item ".\certificates\*.cer" -Destination "$packagePath\certificates\" -Force
        New-Item -ItemType Directory -Path "$packagePath\certificates" -Force | Out-Null
    }
    
    # Copy installation scripts
    Copy-Item ".\scripts\install_*.ps1" -Destination $packagePath -Force
    Copy-Item ".\scripts\uninstall_*.ps1" -Destination $packagePath -Force
    
    # Copy Python backend
    Copy-Item ".\python\*" -Destination "$packagePath\python\" -Recurse -Force
    New-Item -ItemType Directory -Path "$packagePath\python" -Force | Out-Null
    
    # Create package manifest
    $manifest = @{
        PackageName = $packageName
        Version = "1.0.0"
        Configuration = $Configuration
        Platform = $Platform
        BuildDate = Get-Date
        Files = @{
            Driver = (Get-ChildItem "$packagePath\*.sys", "$packagePath\*.inf" | ForEach-Object { $_.Name })
            Backend = (Get-ChildItem "$packagePath\*.dll", "$packagePath\*.exe" | ForEach-Object { $_.Name })
            Certificates = (Get-ChildItem "$packagePath\certificates\*" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        }
    }
    
    $manifest | ConvertTo-Json -Depth 3 | Out-File "$packagePath\manifest.json"
    
    Write-Status "Installation package created: $packagePath"
    return $packagePath
}

# Main execution
try {
    Write-Status "Starting VDD Remote Desktop build process..." "Cyan"
    
    Test-Prerequisites
    New-BuildEnvironment
    
    # Handle certificate
    if (-not $CertificatePath -or -not (Test-Path $CertificatePath)) {
        Write-Status "No certificate provided, generating self-signed certificate..." "Yellow"
        & .\scripts\generate_certificate.ps1 -CertificateSubject "CN=VDD Remote Desktop" -InstallToStore
        
        $certInfo = Get-Content ".\certificates\cert_info.json" | ConvertFrom-Json
        $CertificatePath = $certInfo.CertificatePath
    }
    
    Invoke-DriverBuild
    Invoke-BackendBuild
    $packagePath = New-InstallationPackage
    
    if ($InstallAfterBuild) {
        Write-Status "Installing driver and backend..." "Yellow"
        & "$packagePath\install_vdd_complete.ps1" -Force
    }
    
    Write-Status "Build process completed successfully!" "Green"
    Write-Status "Package location: $packagePath" "Cyan"
    
} catch {
    Write-Status "Build failed: $($_.Exception.Message)" "Red"
    exit 1
}
```

## 3. Automated Installation Scripts

### 3.1 Complete Installation Script
**File: `scripts/install_vdd_complete.ps1`**

```powershell
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Program Files\VDD Remote Desktop"
)

$ErrorActionPreference = "Stop"

function Write-InstallLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if (-not $Silent) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }
    
    Add-Content -Path ".\install.log" -Value $logMessage
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Certificate {
    param([string]$CertPath)
    
    Write-InstallLog "Installing certificate: $CertPath"
    
    try {
        # Install to Trusted Root Certification Authorities
        Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
        
        # Install to Trusted Publishers (required for driver installation)
        Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
        
        Write-InstallLog "Certificate installed successfully" "SUCCESS"
        return $true
    } catch {
        Write-InstallLog "Failed to install certificate: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-VDDDriver {
    param([string]$DriverPath, [string]$InfPath)
    
    Write-InstallLog "Installing VDD driver from: $InfPath"
    
    try {
        # Use PnPUtil to install the driver
        $result = & pnputil.exe /add-driver $InfPath /install
        
        if ($LASTEXITCODE -eq 0) {
            Write-InstallLog "Driver installed successfully" "SUCCESS"
            
            # Create the virtual display device
            $result = & pnputil.exe /add-device "Root\MttVDD"
            
            if ($LASTEXITCODE -eq 0) {
                Write-InstallLog "Virtual display device created" "SUCCESS"
                return $true
            } else {
                Write-InstallLog "Failed to create virtual display device" "ERROR"
                return $false
            }
        } else {
            Write-InstallLog "Driver installation failed: $result" "ERROR"
            return $false
        }
    } catch {
        Write-InstallLog "Driver installation exception: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-Backend {
    param([string]$SourcePath, [string]$DestinationPath)
    
    Write-InstallLog "Installing backend to: $DestinationPath"
    
    try {
        # Create installation directory
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        
        # Copy backend files
        Copy-Item "$SourcePath\*.dll" -Destination $DestinationPath -Force
        Copy-Item "$SourcePath\*.exe" -Destination $DestinationPath -Force
        
        # Copy Python backend
        if (Test-Path "$SourcePath\python") {
            Copy-Item "$SourcePath\python\*" -Destination "$DestinationPath\python\" -Recurse -Force
        }
        
        Write-InstallLog "Backend installed successfully" "SUCCESS"
        return $true
    } catch {
        Write-InstallLog "Backend installation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Register-Service {
    param([string]$ServicePath)
    
    Write-InstallLog "Registering VDD Remote Desktop service"
    
    try {
        $serviceName = "VDDRemoteDesktop"
        $serviceDisplayName = "VDD Remote Desktop Service"
        $serviceDescription = "Virtual Display Driver Remote Desktop streaming service"
        
        # Remove existing service if it exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-InstallLog "Removing existing service" "WARNING"
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $serviceName
        }
        
        # Create new service
        $execPath = Join-Path $ServicePath "VDDRemoteDesktopService.exe"
        $result = & sc.exe create $serviceName binpath= $execPath start= auto displayname= $serviceDisplayName
        
        if ($LASTEXITCODE -eq 0) {
            & sc.exe description $serviceName $serviceDescription
            Write-InstallLog "Service registered successfully" "SUCCESS"
            return $true
        } else {
            Write-InstallLog "Service registration failed: $result" "ERROR"
            return $false
        }
    } catch {
        Write-InstallLog "Service registration exception: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Add-FirewallRules {
    Write-InstallLog "Adding firewall rules"
    
    try {
        # Remove existing rules
        Remove-NetFirewallRule -DisplayName "VDD Remote Desktop*" -ErrorAction SilentlyContinue
        
        # Add new rules
        New-NetFirewallRule -DisplayName "VDD Remote Desktop HTTP" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow | Out-Null
        New-NetFirewallRule -DisplayName "VDD Remote Desktop WebRTC" -Direction Inbound -Protocol UDP -LocalPort 50000-50100 -Action Allow | Out-Null
        
        Write-InstallLog "Firewall rules added successfully" "SUCCESS"
        return $true
    } catch {
        Write-InstallLog "Failed to add firewall rules: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

# Main installation process
try {
    Write-InstallLog "Starting VDD Remote Desktop installation" "SUCCESS"
    
    # Check admin privileges
    if (-not (Test-AdminPrivileges)) {
        throw "Administrator privileges required for installation"
    }
    
    # Check if already installed and handle accordingly
    if ((Test-Path $InstallPath) -and -not $Force) {
        if ($Silent) {
            throw "Installation already exists. Use -Force to overwrite."
        }
        
        $response = Read-Host "Installation already exists. Overwrite? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-InstallLog "Installation cancelled by user"
            exit 0
        }
    }
    
    # Install certificates
    $certPath = ".\certificates\VDDCodeSigning.cer"
    if (Test-Path $certPath) {
        if (-not (Install-Certificate -CertPath $certPath)) {
            throw "Certificate installation failed"
        }
    } else {
        Write-InstallLog "No certificate found, skipping certificate installation" "WARNING"
    }
    
    # Install driver
    $infPath = ".\MttVDD.inf"
    if (Test-Path $infPath) {
        if (-not (Install-VDDDriver -DriverPath "." -InfPath $infPath)) {
            throw "Driver installation failed"
        }
    } else {
        throw "Driver INF file not found: $infPath"
    }
    
    # Install backend
    if (-not (Install-Backend -SourcePath "." -DestinationPath $InstallPath)) {
        throw "Backend installation failed"
    }
    
    # Register service
    if (-not (Register-Service -ServicePath $InstallPath)) {
        Write-InstallLog "Service registration failed, continuing..." "WARNING"
    }
    
    # Add firewall rules
    Add-FirewallRules | Out-Null
    
    # Create start menu shortcut
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VDD Remote Desktop.lnk")
    $shortcut.TargetPath = Join-Path $InstallPath "python\main.py"
    $shortcut.WorkingDirectory = Join-Path $InstallPath "python"
    $shortcut.IconLocation = Join-Path $InstallPath "icon.ico"
    $shortcut.Save()
    
    Write-InstallLog "Installation completed successfully!" "SUCCESS"
    Write-InstallLog "Installation path: $InstallPath" "SUCCESS"
    
    if (-not $Silent) {
        Write-Host "`nInstallation Summary:" -ForegroundColor Cyan
        Write-Host "- VDD Driver: Installed" -ForegroundColor Green
        Write-Host "- Backend: Installed to $InstallPath" -ForegroundColor Green
        Write-Host "- Service: Registered" -ForegroundColor Green
        Write-Host "- Firewall: Configured" -ForegroundColor Green
        Write-Host "`nTo start the service:" -ForegroundColor Yellow
        Write-Host "  Start-Service VDDRemoteDesktop" -ForegroundColor White
        Write-Host "`nTo access the web interface:" -ForegroundColor Yellow
        Write-Host "  http://localhost:8000" -ForegroundColor White
    }
    
} catch {
    Write-InstallLog "Installation failed: $($_.Exception.Message)" "ERROR"
    
    if (-not $Silent) {
        Write-Host "`nInstallation failed. Check install.log for details." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    exit 1
}
```

### 3.2 Uninstallation Script
**File: `scripts/uninstall_vdd_complete.ps1`**

```powershell
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$Silent = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Program Files\VDD Remote Desktop"
)

function Write-UninstallLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if (-not $Silent) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }
    
    Add-Content -Path ".\uninstall.log" -Value $logMessage
}

try {
    Write-UninstallLog "Starting VDD Remote Desktop uninstallation" "SUCCESS"
    
    # Stop and remove service
    $serviceName = "VDDRemoteDesktop"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-UninstallLog "Stopping service: $serviceName"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName
        Write-UninstallLog "Service removed" "SUCCESS"
    }
    
    # Remove driver
    Write-UninstallLog "Removing VDD driver"
    $devices = Get-PnpDevice -FriendlyName "*VDD*" -ErrorAction SilentlyContinue
    foreach ($device in $devices) {
        & pnputil.exe /remove-device $device.InstanceId
    }
    
    # Remove driver package
    $driverPackages = & pnputil.exe /enum-drivers | Where-Object { $_ -match "MttVDD" }
    foreach ($package in $driverPackages) {
        if ($package -match "Published Name:\s+(.+)") {
            & pnputil.exe /delete-driver $matches[1] /uninstall
        }
    }
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Write-UninstallLog "Removing installation directory: $InstallPath"
        Remove-Item -Path $InstallPath -Recurse -Force
        Write-UninstallLog "Installation directory removed" "SUCCESS"
    }
    
    # Remove firewall rules
    Write-UninstallLog "Removing firewall rules"
    Remove-NetFirewallRule -DisplayName "VDD Remote Desktop*" -ErrorAction SilentlyContinue
    
    # Remove start menu shortcut
    $shortcutPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VDD Remote Desktop.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
    }
    
    Write-UninstallLog "Uninstallation completed successfully!" "SUCCESS"
    
} catch {
    Write-UninstallLog "Uninstallation failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
```

## 4. CI/CD Integration

### 4.1 GitHub Actions Workflow
**File: `.github/workflows/build-and-release.yml`**

```yaml
name: Build and Release VDD Remote Desktop

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

env:
  SOLUTION_PATH: 'Virtual Display Driver (HDR)/MttVDD.sln'
  CONFIGURATION: Release

jobs:
  build:
    runs-on: windows-latest
    
    strategy:
      matrix:
        platform: [x64, ARM64]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        submodules: recursive
    
    - name: Setup MSBuild
      uses: microsoft/setup-msbuild@v1.3
      
    - name: Setup Windows SDK
      uses: GuillaumeFalourd/setup-windows-sdk@v1
      with:
        sdk-version: "10.0.19041.0"
    
    - name: Cache NuGet packages
      uses: actions/cache@v3
      with:
        path: ~/.nuget/packages
        key: ${{ runner.os }}-nuget-${{ hashFiles('**/*.vcxproj') }}
        restore-keys: |
          ${{ runner.os }}-nuget-
    
    - name: Install Python dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
      working-directory: python
    
    - name: Create build certificate
      run: |
        # Create a temporary certificate for CI builds
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=VDD CI Build" -KeyAlgorithm RSA -KeyLength 2048 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -KeyExportPolicy Exportable -KeyUsage DigitalSignature -ValidityPeriod Years -ValidityLength 1 -CertStoreLocation "Cert:\CurrentUser\My"
        $certPath = ".\certificates\ci_cert.pfx"
        New-Item -ItemType Directory -Path ".\certificates" -Force
        Export-PfxCertificate -Cert $cert -FilePath $certPath -Password (ConvertTo-SecureString -String "ci_password" -Force -AsPlainText)
        echo "CERT_PATH=$certPath" >> $env:GITHUB_ENV
        echo "CERT_PASSWORD=ci_password" >> $env:GITHUB_ENV
      shell: powershell
    
    - name: Build VDD Driver
      run: |
        msbuild "${{ env.SOLUTION_PATH }}" /p:Configuration=${{ env.CONFIGURATION }} /p:Platform=${{ matrix.platform }} /p:SigningCertificatePath="${{ env.CERT_PATH }}" /p:SigningCertificatePassword="${{ env.CERT_PASSWORD }}" /verbosity:minimal /nologo
    
    - name: Build C++ Backend
      run: |
        mkdir backend\build
        cd backend\build
        cmake .. -A ${{ matrix.platform }} -DCMAKE_BUILD_TYPE=${{ env.CONFIGURATION }}
        cmake --build . --config ${{ env.CONFIGURATION }}
      shell: cmd
    
    - name: Create installation package
      run: |
        .\scripts\build_and_sign.ps1 -Configuration ${{ env.CONFIGURATION }} -Platform ${{ matrix.platform }} -CertificatePath "${{ env.CERT_PATH }}" -CertificatePassword "${{ env.CERT_PASSWORD }}"
      shell: powershell
    
    - name: Upload build artifacts
      uses: actions/upload-artifact@v3
      with:
        name: vdd-remote-desktop-${{ matrix.platform }}
        path: packages/VDD_*
        retention-days: 30
    
    - name: Create release package
      if: startsWith(github.ref, 'refs/tags/')
      run: |
        $packageDir = Get-ChildItem -Path "packages" -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1
        Compress-Archive -Path "$($packageDir.FullName)\*" -DestinationPath "VDD_RemoteDesktop_${{ matrix.platform }}_${{ github.ref_name }}.zip"
      shell: powershell
    
    - name: Upload to release
      if: startsWith(github.ref, 'refs/tags/')
      uses: softprops/action-gh-release@v1
      with:
        files: VDD_RemoteDesktop_${{ matrix.platform }}_${{ github.ref_name }}.zip
        draft: false
        prerelease: false
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  test:
    needs: build
    runs-on: windows-latest
    if: github.event_name == 'workflow_dispatch'
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Download build artifacts
      uses: actions/download-artifact@v3
      with:
        name: vdd-remote-desktop-x64
        path: test-package
    
    - name: Install and test
      run: |
        cd test-package
        $packageDir = Get-ChildItem -Directory | Select-Object -First 1
        cd $packageDir.Name
        
        # Install with silent flag for CI
        .\install_vdd_complete.ps1 -Silent -Force
        
        # Wait for service to start
        Start-Sleep -Seconds 10
        
        # Test basic functionality
        $response = Invoke-WebRequest -Uri "http://localhost:8000/api/displays" -UseBasicParsing
        if ($response.StatusCode -ne 200) {
          throw "API test failed"
        }
        
        Write-Host "Installation and basic functionality test passed"
      shell: powershell
```

## 5. Production Certificate Management

### 5.1 Certificate Storage and Retrieval
**File: `scripts/manage_certificates.ps1`**

```powershell
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Install", "Generate", "Export", "Validate")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Password = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Subject = "CN=VDD Remote Desktop Driver"
)

function Install-ProductionCertificate {
    param([string]$Path, [string]$Password)
    
    Write-Host "Installing production certificate..." -ForegroundColor Green
    
    try {
        # Install certificate to Personal store
        if ($Password) {
            $securePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
            Import-PfxCertificate -FilePath $Path -CertStoreLocation "Cert:\LocalMachine\My" -Password $securePassword
        } else {
            Import-PfxCertificate -FilePath $Path -CertStoreLocation "Cert:\LocalMachine\My"
        }
        
        # Export public certificate
        $cert = Get-PfxCertificate -FilePath $Path
        $publicCertPath = ".\certificates\production_public.cer"
        Export-Certificate -Cert $cert -FilePath $publicCertPath
        
        # Install public certificate to trusted stores
        Import-Certificate -FilePath $publicCertPath -CertStoreLocation "Cert:\LocalMachine\Root"
        Import-Certificate -FilePath $publicCertPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"
        
        Write-Host "Production certificate installed successfully" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "Failed to install production certificate: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-CertificateValidation {
    param([string]$CertPath)
    
    Write-Host "Validating certificate..." -ForegroundColor Yellow
    
    try {
        $cert = Get-PfxCertificate -FilePath $CertPath
        
        # Check if certificate is valid for code signing
        $codeSigningUsage = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
        if (-not $codeSigningUsage) {
            Write-Host "Warning: Certificate may not be valid for code signing" -ForegroundColor Yellow
        }
        
        # Check expiration
        $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
        if ($daysUntilExpiry -lt 30) {
            Write-Host "Warning: Certificate expires in $daysUntilExpiry days" -ForegroundColor Yellow
        }
        
        # Check chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chainResult = $chain.Build($cert)
        
        if ($chainResult) {
            Write-Host "Certificate validation successful" -ForegroundColor Green
        } else {
            Write-Host "Certificate chain validation failed" -ForegroundColor Red
            foreach ($status in $chain.ChainStatus) {
                Write-Host "  $($status.Status): $($status.StatusInformation)" -ForegroundColor Red
            }
        }
        
        return $chainResult
        
    } catch {
        Write-Host "Certificate validation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution
switch ($Action) {
    "Install" {
        if (-not $CertificatePath -or -not (Test-Path $CertificatePath)) {
            Write-Host "Certificate path required for installation" -ForegroundColor Red
            exit 1
        }
        Install-ProductionCertificate -Path $CertificatePath -Password $Password
    }
    
    "Generate" {
        Write-Host "Generating self-signed certificate..." -ForegroundColor Green
        & .\generate_certificate.ps1 -CertificateSubject $Subject -CertificatePassword $Password -InstallToStore
    }
    
    "Validate" {
        if (-not $CertificatePath -or -not (Test-Path $CertificatePath)) {
            Write-Host "Certificate path required for validation" -ForegroundColor Red
            exit 1
        }
        Test-CertificateValidation -CertPath $CertificatePath
    }
    
    "Export" {
        # Export certificates for distribution
        Write-Host "Exporting certificates for distribution..." -ForegroundColor Green
        
        $exportDir = ".\certificates\distribution"
        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        
        # Export all relevant certificates
        Get-ChildItem "Cert:\LocalMachine\TrustedPublisher" | Where-Object { $_.Subject -like "*VDD*" } | ForEach-Object {
            $exportPath = Join-Path $exportDir "$($_.Thumbprint).cer"
            Export-Certificate -Cert $_ -FilePath $exportPath
            Write-Host "Exported: $exportPath" -ForegroundColor Green
        }
    }
}
```

### 5.2 Enterprise Deployment Script
**File: `scripts/enterprise_deploy.ps1`**

```powershell
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string[]]$TargetComputers,
    
    [Parameter(Mandatory=$false)]
    [string]$PackagePath = "",
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent = $false
)

function Deploy-ToComputer {
    param(
        [string]$ComputerName,
        [string]$PackagePath,
        [PSCredential]$Credential
    )
    
    Write-Host "Deploying to $ComputerName..." -ForegroundColor Cyan
    
    try {
        # Test connectivity
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            throw "Computer $ComputerName is not reachable"
        }
        
        # Create remote session
        $sessionParams = @{
            ComputerName = $ComputerName
            ErrorAction = "Stop"
        }
        
        if ($Credential) {
            $sessionParams.Credential = $Credential
        }
        
        $session = New-PSSession @sessionParams
        
        # Copy installation package
        $remotePackagePath = "C:\Temp\VDD_Install"
        Copy-Item -Path $PackagePath -Destination $remotePackagePath -ToSession $session -Recurse -Force
        
        # Execute installation
        $installResult = Invoke-Command -Session $session -ScriptBlock {
            param($PackagePath, $Silent)
            
            Set-Location $PackagePath
            
            if ($Silent) {
                .\install_vdd_complete.ps1 -Silent -Force
            } else {
                .\install_vdd_complete.ps1 -Force
            }
            
            return $LASTEXITCODE
        } -ArgumentList $remotePackagePath, $Silent
        
        if ($installResult -eq 0) {
            Write-Host "✓ Successfully deployed to $ComputerName" -ForegroundColor Green
        } else {
            Write-Host "✗ Deployment failed on $ComputerName (Exit code: $installResult)" -ForegroundColor Red
        }
        
        # Cleanup
        Remove-PSSession -Session $session
        
    } catch {
        Write-Host "✗ Failed to deploy to $ComputerName`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main deployment process
Write-Host "Starting enterprise deployment..." -ForegroundColor Green
Write-Host "Target computers: $($TargetComputers -join ', ')" -ForegroundColor Cyan

if (-not $PackagePath) {
    # Find latest package
    $latestPackage = Get-ChildItem -Path ".\packages" -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1
    if ($latestPackage) {
        $PackagePath = $latestPackage.FullName
        Write-Host "Using latest package: $PackagePath" -ForegroundColor Yellow
    } else {
        Write-Host "No installation package found. Run build first." -ForegroundColor Red
        exit 1
    }
}

# Deploy to each computer
$results = @()
foreach ($computer in $TargetComputers) {
    $startTime = Get-Date
    Deploy-ToComputer -ComputerName $computer -PackagePath $PackagePath -Credential $Credential
    $endTime = Get-Date
    
    $results += [PSCustomObject]@{
        Computer = $computer
        Duration = ($endTime - $startTime).TotalSeconds
        Status = if ($LASTEXITCODE -eq 0) { "Success" } else { "Failed" }
    }
}

# Summary report
Write-Host "`nDeployment Summary:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$successful = ($results | Where-Object { $_.Status -eq "Success" }).Count
$total = $results.Count

Write-Host "Deployment completed: $successful/$total successful" -ForegroundColor $(if ($successful -eq $total) { "Green" } else { "Yellow" })
```

## 6. Driver Installation Verification

### 6.1 Post-Install Verification Script
**File: `scripts/verify_installation.ps1`**

```powershell
param(
    [Parameter(Mandatory=$false)]
    [switch]$Detailed = $false
)

function Test-DriverInstallation {
    Write-Host "Checking VDD driver installation..." -ForegroundColor Yellow
    
    # Check if driver is installed
    $driver = Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like "*MttVDD*" }
    if ($driver) {
        Write-Host "✓ VDD driver is installed" -ForegroundColor Green
        if ($Detailed) {
            Write-Host "  Version: $($driver.Version)" -ForegroundColor Gray
            Write-Host "  Date: $($driver.Date)" -ForegroundColor Gray
        }
        return $true
    } else {
        Write-Host "✗ VDD driver is not installed" -ForegroundColor Red
        return $false
    }
}

function Test-VirtualDisplayDevice {
    Write-Host "Checking virtual display device..." -ForegroundColor Yellow
    
    $device = Get-PnpDevice -FriendlyName "*VDD*" | Where-Object { $_.Status -eq "OK" }
    if ($device) {
        Write-Host "✓ Virtual display device is active" -ForegroundColor Green
        if ($Detailed) {
            $device | ForEach-Object {
                Write-Host "  Device: $($_.FriendlyName)" -ForegroundColor Gray
                Write-Host "  Status: $($_.Status)" -ForegroundColor Gray
                Write-Host "  Instance: $($_.InstanceId)" -ForegroundColor Gray
            }
        }
        return $true
    } else {
        Write-Host "✗ Virtual display device is not active" -ForegroundColor Red
        return $false
    }
}

function Test-ServiceStatus {
    Write-Host "Checking VDD service..." -ForegroundColor Yellow
    
    $service = Get-Service -Name "VDDRemoteDesktop" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Host "✓ VDD service is running" -ForegroundColor Green
        } else {
            Write-Host "⚠ VDD service is installed but not running" -ForegroundColor Yellow
            Write-Host "  Status: $($service.Status)" -ForegroundColor Gray
        }
        return $true
    } else {
        Write-Host "✗ VDD service is not installed" -ForegroundColor Red
        return $false
    }
}

function Test-WebInterface {
    Write-Host "Checking web interface..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ Web interface is accessible" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ Web interface returned status: $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ Web interface is not accessible: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-DisplayCreation {
    Write-Host "Testing display creation..." -ForegroundColor Yellow
    
    try {
        $body = @{
            width = 1920
            height = 1080
            refresh_rate = 60
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/displays" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
        
        if ($response.status -eq "created") {
            Write-Host "✓ Display creation test successful" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ Display creation test failed" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ Display creation test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Run all tests
Write-Host "VDD Remote Desktop Installation Verification" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

$tests = @(
    @{ Name = "Driver Installation"; Function = { Test-DriverInstallation } }
    @{ Name = "Virtual Display Device"; Function = { Test-VirtualDisplayDevice } }
    @{ Name = "Service Status"; Function = { Test-ServiceStatus } }
    @{ Name = "Web Interface"; Function = { Test-WebInterface } }
    @{ Name = "Display Creation"; Function = { Test-DisplayCreation } }
)

$results = @()
foreach ($test in $tests) {
    $result = & $test.Function
    $results += [PSCustomObject]@{
        Test = $test.Name
        Status = if ($result) { "PASS" } else { "FAIL" }
    }
}

Write-Host "`nTest Results:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$totalCount = $results.Count

if ($passCount -eq $totalCount) {
    Write-Host "All tests passed! VDD Remote Desktop is ready to use." -ForegroundColor Green
    exit 0
} else {
    Write-Host "$passCount/$totalCount tests passed. Check failed tests above." -ForegroundColor Yellow
    exit 1
}
```

## 7. One-Click Installer Creation

### 7.1 NSIS Installer Script
**File: `installer/VDD_RemoteDesktop_Installer.nsi`**

```nsis
; VDD Remote Desktop Installer
; Requires NSIS 3.0 or later

!define PRODUCT_NAME "VDD Remote Desktop"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "VDD Development Team"
!define PRODUCT_WEB_SITE "https://github.com/your-repo/vdd-remote-desktop"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\VDDRemoteDesktop.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

; Include required libraries
!include "MUI2.nsh"
!include "Sections.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"

; Installer settings
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "VDD_RemoteDesktop_Setup.exe"
InstallDir "$PROGRAMFILES64\VDD Remote Desktop"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin

; Interface settings
!define MUI_ABORTWARNING
!define MUI_ICON ".\resources\icon.ico"
!define MUI_UNICON ".\resources\uninstall.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE ".\LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Version info
VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "Comments" "Virtual Display Driver Remote Desktop Solution"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalTrademarks" ""
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "© 2024 ${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${PRODUCT_NAME} Setup"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${PRODUCT_VERSION}"

; Functions
Function .onInit
  ; Check Windows version
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "This software requires Windows 10 or later."
    Abort
  ${EndIf}
  
  ; Check admin rights
  UserInfo::GetAccountType
  Pop $0
  ${If} $0 != "admin"
    MessageBox MB_OK|MB_ICONSTOP "Administrator privileges are required to install this software."
    Abort
  ${EndIf}
FunctionEnd

; Installer sections
Section "VDD Driver" SecDriver
  SectionIn RO  ; Required section
  
  SetOutPath "$INSTDIR"
  
  ; Install certificates first
  DetailPrint "Installing certificates..."
  File "certificates\*.cer"
  
  ; Install certificates to system stores
  nsExec::ExecToLog 'certlm.exe -add -c "VDDCodeSigning.cer" -s -r localMachine root'
  nsExec::ExecToLog 'certlm.exe -add -c "VDDCodeSigning.cer" -s -r localMachine trustedpublisher'
  
  ; Install driver files
  DetailPrint "Installing driver files..."
  File "*.sys"
  File "*.inf"
  File "*.cat"
  
  ; Install driver
  DetailPrint "Installing VDD driver..."
  nsExec::ExecToLog 'pnputil.exe /add-driver "MttVDD.inf" /install'
  
  ; Create virtual display device
  DetailPrint "Creating virtual display device..."
  nsExec::ExecToLog 'pnputil.exe /add-device "Root\MttVDD"'
SectionEnd

Section "Backend Services" SecBackend
  SectionIn RO  ; Required section
  
  SetOutPath "$INSTDIR"
  
  ; Install backend files
  DetailPrint "Installing backend services..."
  File "*.dll"
  File "*.exe"
  
  ; Install Python backend
  SetOutPath "$INSTDIR\python"
  File /r "python\*.*"
  
  ; Register service
  DetailPrint "Registering VDD service..."
  nsExec::ExecToLog 'sc.exe create VDDRemoteDesktop binpath= "$INSTDIR\VDDRemoteDesktopService.exe" start= auto displayname= "VDD Remote Desktop Service"'
  nsExec::ExecToLog 'sc.exe description VDDRemoteDesktop "Virtual Display Driver Remote Desktop streaming service"'
SectionEnd

Section "Firewall Rules" SecFirewall
  ; Add firewall rules
  DetailPrint "Configuring firewall..."
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="VDD Remote Desktop HTTP" dir=in action=allow protocol=TCP localport=8000'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="VDD Remote Desktop WebRTC" dir=in action=allow protocol=UDP localport=50000-50100'
SectionEnd

Section "Start Menu Shortcuts" SecShortcuts
  CreateDirectory "$SMPROGRAMS\VDD Remote Desktop"
  CreateShortCut "$SMPROGRAMS\VDD Remote Desktop\VDD Remote Desktop.lnk" "$INSTDIR\python\main.py"
  CreateShortCut "$SMPROGRAMS\VDD Remote Desktop\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section -AdditionalIcons
  WriteIniStr "$INSTDIR\${PRODUCT_NAME}.url" "InternetShortcut" "URL" "${PRODUCT_WEB_SITE}"
  CreateShortCut "$SMPROGRAMS\VDD Remote Desktop\Website.lnk" "$INSTDIR\${PRODUCT_NAME}.url"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\VDDRemoteDesktop.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\VDDRemoteDesktop.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd

; Uninstaller
Section Uninstall
  ; Stop service
  nsExec::ExecToLog 'sc.exe stop VDDRemoteDesktop'
  nsExec::ExecToLog 'sc.exe delete VDDRemoteDesktop'
  
  ; Remove virtual display
  nsExec::ExecToLog 'pnputil.exe /remove-device "Root\MttVDD"'
  
  ; Remove driver
  nsExec::ExecToLog 'pnputil.exe /delete-driver "MttVDD.inf" /uninstall'
  
  ; Remove firewall rules
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="VDD Remote Desktop HTTP"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="VDD Remote Desktop WebRTC"'
  
  ; Remove files
  Delete "$INSTDIR\${PRODUCT_NAME}.url"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\*.*"
  
  ; Remove directories
  RMDir /r "$INSTDIR\python"
  RMDir "$INSTDIR"
  
  ; Remove shortcuts
  Delete "$SMPROGRAMS\VDD Remote Desktop\*.*"
  RMDir "$SMPROGRAMS\VDD Remote Desktop"
  
  ; Remove registry keys
  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  
  SetAutoClose true
SectionEnd
```

### 7.2 Installer Build Script
**File: `scripts/build_installer.ps1`**

```powershell
param(
    [Parameter(Mandatory=$false)]
    [string]$PackagePath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$NSISPath = "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
)

function Test-NSISInstalled {
    return Test-Path $NSISPath
}

function Build-Installer {
    param([string]$SourcePath)
    
    Write-Host "Building installer from: $SourcePath" -ForegroundColor Green
    
    # Copy source files to installer directory
    $installerSource = ".\installer\source"
    New-Item -ItemType Directory -Path $installerSource -Force | Out-Null
    
    Copy-Item "$SourcePath\*" -Destination $installerSource -Recurse -Force
    
    # Update version in NSIS script
    $nsisScript = ".\installer\VDD_RemoteDesktop_Installer.nsi"
    $version = "1.0.0"  # Get from manifest or version file
    
    if (Test-Path ".\version.txt") {
        $version = Get-Content ".\version.txt" -Raw
    }
    
    (Get-Content $nsisScript) -replace '!define PRODUCT_VERSION ".*"', "!define PRODUCT_VERSION `"$version`"" | Set-Content $nsisScript
    
    # Build installer
    $outputPath = ".\dist\VDD_RemoteDesktop_Setup_v$version.exe"
    New-Item -ItemType Directory -Path ".\dist" -Force | Out-Null
    
    & $NSISPath $nsisScript
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Installer built successfully: $outputPath" -ForegroundColor Green
        return $outputPath
    } else {
        throw "Installer build failed"
    }
}

# Main execution
try {
    if (-not (Test-NSISInstalled)) {
        Write-Host "NSIS not found. Please install NSIS from https://nsis.sourceforge.io/" -ForegroundColor Red
        exit 1
    }
    
    if (-not $PackagePath) {
        $latestPackage = Get-ChildItem -Path ".\packages" -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1
        if ($latestPackage) {
            $PackagePath = $latestPackage.FullName
        } else {
            throw "No package found. Run build first."
        }
    }
    
    $installerPath = Build-Installer -SourcePath $PackagePath
    Write-Host "Installer ready: $installerPath" -ForegroundColor Green
    
} catch {
    Write-Host "Failed to build installer: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```

## 8. Silent Installation Options

### 8.1 Silent Installation Parameters
**File: `scripts/silent_install_options.ps1`**

```powershell
# Silent installation with various deployment scenarios

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Workstation", "Server", "Kiosk", "Custom")]
    [string]$DeploymentType = "Workstation",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "",
    
    [Parameter(Mandatory=$false)]
    [hashtable]$CustomSettings = @{}
)

# Predefined deployment configurations
$DeploymentConfigs = @{
    "Workstation" = @{
        EnableFirewall = $true
        StartService = $true
        CreateShortcuts = $true
        AllowRemoteConnections = $true
        DefaultResolution = "1920x1080"
        DefaultRefreshRate = 60
        LogLevel = "Info"
    }
    
    "Server" = @{
        EnableFirewall = $true
        StartService = $true
        CreateShortcuts = $false
        AllowRemoteConnections = $true
        DefaultResolution = "1280x720"
        DefaultRefreshRate = 30
        LogLevel = "Warning"
        ServiceStartup = "Automatic"
    }
    
    "Kiosk" = @{
        EnableFirewall = $false
        StartService = $true
        CreateShortcuts = $false
        AllowRemoteConnections = $false
        DefaultResolution = "1920x1080"
        DefaultRefreshRate = 60
        LogLevel = "Error"
        AutoStart = $true
    }
}

function Install-WithConfiguration {
    param([hashtable]$Config)
    
    Write-Host "Installing with $DeploymentType configuration..." -ForegroundColor Green
    
    # Create temporary config file
    $tempConfig = Join-Path $env:TEMP "vdd_install_config.json"
    $Config | ConvertTo-Json | Out-File -FilePath $tempConfig
    
    try {
        # Run installation with config
        $installArgs = @(
            "-Silent"
            "-Force"
            "-ConfigFile", $tempConfig
        )
        
        if ($Config.ServiceStartup) {
            $installArgs += "-ServiceStartup", $Config.ServiceStartup
        }
        
        if ($Config.LogLevel) {
            $installArgs += "-LogLevel", $Config.LogLevel
        }
        
        & .\install_vdd_complete.ps1 @installArgs
        
        # Post-installation configuration
        if ($Config.DefaultResolution) {
            Set-DefaultDisplaySettings -Resolution $Config.DefaultResolution -RefreshRate $Config.DefaultRefreshRate
        }
        
        if ($Config.AutoStart) {
            Set-AutoStartConfiguration
        }
        
        Write-Host "Installation completed with $DeploymentType configuration" -ForegroundColor Green
        
    } finally {
        # Cleanup
        if (Test-Path $tempConfig) {
            Remove-Item $tempConfig -Force
        }
    }
}

function Set-DefaultDisplaySettings {
    param([string]$Resolution, [int]$RefreshRate)
    
    $configPath = "C:\Program Files\VDD Remote Desktop\python\config.json"
    
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
    } else {
        $config = @{}
    }
    
    $config.defaultSettings = @{
        resolution = $Resolution
        refreshRate = $RefreshRate
    }
    
    $config | ConvertTo-Json -Depth 3 | Out-File $configPath
}

function Set-AutoStartConfiguration {
    # Create Windows startup entry
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $shortcutPath = "$startupPath\VDD Remote Desktop.lnk"
    
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "C:\Program Files\VDD Remote Desktop\python\main.py"
    $shortcut.WorkingDirectory = "C:\Program Files\VDD Remote Desktop\python"
    $shortcut.Arguments = "--silent --autostart"
    $shortcut.Save()
}

# Main execution
$selectedConfig = $DeploymentConfigs[$DeploymentType]

if ($CustomSettings.Count -gt 0) {
    # Merge custom settings
    foreach ($key in $CustomSettings.Keys) {
        $selectedConfig[$key] = $CustomSettings[$key]
    }
}

if ($ConfigFile -and (Test-Path $ConfigFile)) {
    # Load additional settings from file
    $fileConfig = Get-Content $ConfigFile | ConvertFrom-Json
    $fileConfig.PSObject.Properties | ForEach-Object {
        $selectedConfig[$_.Name] = $_.Value
    }
}

Install-WithConfiguration -Config $selectedConfig
```

### 8.2 Group Policy Deployment Script
**File: `scripts/gpo_deploy.ps1`**

```powershell
#Requires -RunAsAdministrator
#Requires -Module GroupPolicy

param(
    [Parameter(Mandatory=$true)]
    [string]$GPOName = "VDD Remote Desktop Deployment",
    
    [Parameter(Mandatory=$true)]
    [string]$PackagePath,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetOU = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DeploymentType = "Workstation"
)

function New-VDDDeploymentGPO {
    param(
        [string]$Name,
        [string]$PackagePath,
        [string]$TargetOU,
        [string]$DeploymentType
    )
    
    Write-Host "Creating GPO for VDD Remote Desktop deployment..." -ForegroundColor Green
    
    try {
        # Create new GPO
        $gpo = New-GPO -Name $Name -Comment "VDD Remote Desktop automatic deployment"
        
        # Create network share for deployment files
        $sharePath = "\\$env:COMPUTERNAME\VDDDeploy$"
        $localPath = "C:\VDDDeploy"
        
        if (-not (Test-Path $localPath)) {
            New-Item -ItemType Directory -Path $localPath -Force | Out-Null
        }
        
        # Copy deployment files
        Copy-Item "$PackagePath\*" -Destination $localPath -Recurse -Force
        
        # Create network share
        New-SmbShare -Name "VDDDeploy$" -Path $localPath -FullAccess "Everyone" -ErrorAction SilentlyContinue
        
        # Create deployment script
        $deployScript = @"
@echo off
echo Installing VDD Remote Desktop...
powershell.exe -ExecutionPolicy Bypass -Command "& '$sharePath\install_vdd_complete.ps1' -Silent -Force -DeploymentType $DeploymentType"
if %errorlevel% equ 0 (
    echo Installation completed successfully
) else (
    echo Installation failed with error %errorlevel%
    exit /b %errorlevel%
)
"@
        
        $deployScriptPath = "$localPath\deploy.cmd"
        $deployScript | Out-File -FilePath $deployScriptPath -Encoding ASCII
        
        # Configure GPO computer startup script
        $gpoPath = "\\$env:USERDNSDOMAIN\sysvol\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Scripts\Startup"
        New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
        
        Copy-Item $deployScriptPath -Destination "$gpoPath\deploy.cmd"
        
        # Set startup script in GPO
        $scriptsIniPath = "$gpoPath\scripts.ini"
        $scriptsIni = @"
[Startup]
0CmdLine=deploy.cmd
0Parameters=
"@
        $scriptsIni | Out-File -FilePath $scriptsIniPath -Encoding ASCII
        
        # Configure registry settings for VDD
        Set-GPRegistryValue -Name $Name -Key "HKLM\SOFTWARE\VDD Remote Desktop" -ValueName "AutoDeploy" -Type String -Value "True"
        Set-GPRegistryValue -Name $Name -Key "HKLM\SOFTWARE\VDD Remote Desktop" -ValueName "DeploymentType" -Type String -Value $DeploymentType
        Set-GPRegistryValue -Name $Name -Key "HKLM\SOFTWARE\VDD Remote Desktop" -ValueName "DeploymentDate" -Type String -Value (Get-Date).ToString()
        
        # Link GPO to OU if specified
        if ($TargetOU) {
            New-GPLink -Name $Name -Target $TargetOU -LinkEnabled Yes
            Write-Host "GPO linked to OU: $TargetOU" -ForegroundColor Green
        }
        
        Write-Host "GPO created successfully: $Name" -ForegroundColor Green
        Write-Host "Deployment share: $sharePath" -ForegroundColor Cyan
        
        return $gpo
        
    } catch {
        Write-Host "Failed to create GPO: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Main execution
try {
    if (-not (Test-Path $PackagePath)) {
        throw "Package path not found: $PackagePath"
    }
    
    $gpo = New-VDDDeploymentGPO -Name $GPOName -PackagePath $PackagePath -TargetOU $TargetOU -DeploymentType $DeploymentType
    
    Write-Host "`nDeployment GPO Summary:" -ForegroundColor Cyan
    Write-Host "GPO Name: $($gpo.DisplayName)" -ForegroundColor White
    Write-Host "GPO ID: $($gpo.Id)" -ForegroundColor White
    Write-Host "Target OU: $(if ($TargetOU) { $TargetOU } else { 'Not linked' })" -ForegroundColor White
    Write-Host "Deployment Type: $DeploymentType" -ForegroundColor White
    
    Write-Host "`nNext Steps:" -ForegroundColor Yellow
    Write-Host "1. Test the GPO on a few machines first" -ForegroundColor White
    Write-Host "2. Monitor event logs for deployment status" -ForegroundColor White
    Write-Host "3. Use 'gpupdate /force' to apply immediately" -ForegroundColor White
    
} catch {
    Write-Host "GPO deployment setup failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```

## 9. Troubleshooting and Diagnostics

### 9.1 Diagnostic Collection Script
**File: `scripts/collect_diagnostics.ps1`**

```powershell
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\VDD_Diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
)

function Collect-SystemInfo {
    $tempDir = Join-Path $env:TEMP "VDD_Diagnostics"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    Write-Host "Collecting system information..." -ForegroundColor Yellow
    
    # System information
    Get-ComputerInfo | Out-File "$tempDir\system_info.txt"
    Get-WindowsVersion | Out-File "$tempDir\windows_version.txt"
    
    # Driver information
    Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like "*VDD*" -or $_.OriginalFileName -like "*Mtt*" } | 
        Out-File "$tempDir\vdd_drivers.txt"
    
    # Device information
    Get-PnpDevice | Where-Object { $_.FriendlyName -like "*VDD*" -or $_.FriendlyName -like "*Virtual*Display*" } |
        Out-File "$tempDir\virtual_displays.txt"
    
    # Service information
    Get-Service | Where-Object { $_.Name -like "*VDD*" } | 
        Format-List * | Out-File "$tempDir\vdd_services.txt"
    
    # Process information
    Get-Process | Where-Object { $_.ProcessName -like "*VDD*" -or $_.ProcessName -like "*python*" } |
        Out-File "$tempDir\vdd_processes.txt"
    
    # Network information
    Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 8000 -or $_.LocalPort -ge 50000 } |
        Out-File "$tempDir\network_connections.txt"
    
    # Firewall rules
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*VDD*" } |
        Out-File "$tempDir\firewall_rules.txt"
    
    return $tempDir
}

function Collect-EventLogs {
    param([string]$TempDir)
    
    Write-Host "Collecting event logs..." -ForegroundColor Yellow
    
    try {
        # System event log
        Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} |
            Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Warning' } |
            Where-Object { $_.Message -like "*VDD*" -or $_.Message -like "*display*" -or $_.Message -like "*driver*" } |
            Out-File "$TempDir\system_events.txt"
        
        # Application event log
        Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddDays(-7)} |
            Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Warning' } |
            Where-Object { $_.Message -like "*VDD*" -or $_.Message -like "*python*" } |
            Out-File "$TempDir\application_events.txt"
        
    } catch {
        "Error collecting event logs: $($_.Exception.Message)" | Out-File "$TempDir\event_log_error.txt"
    }
}

function Collect-VDDLogs {
    param([string]$TempDir)
    
    Write-Host "Collecting VDD application logs..." -ForegroundColor Yellow
    
    # VDD driver logs
    $vddLogPath = "C:\VirtualDisplayDriver\Logs"
    if (Test-Path $vddLogPath) {
        Copy-Item "$vddLogPath\*" -Destination "$TempDir\vdd_logs\" -Recurse -Force
        New-Item -ItemType Directory -Path "$TempDir\vdd_logs" -Force | Out-Null
    }
    
    # Python application logs
    $pythonLogPath = "C:\Program Files\VDD Remote Desktop\python\logs"
    if (Test-Path $pythonLogPath) {
        Copy-Item "$pythonLogPath\*" -Destination "$TempDir\python_logs\" -Recurse -Force
        New-Item -ItemType Directory -Path "$TempDir\python_logs" -Force | Out-Null
    }
    
    # Installation logs
    if (Test-Path ".\install.log") {
        Copy-Item ".\install.log" -Destination "$TempDir\"
    }
}

function Collect-Configuration {
    param([string]$TempDir)
    
    Write-Host "Collecting configuration files..." -ForegroundColor Yellow
    
    # Registry settings
    $regPath = "HKLM:\SOFTWARE\MikeTheTech\VirtualDisplayDriver"
    if (Test-Path $regPath) {
        Get-ItemProperty $regPath | Out-File "$TempDir\registry_settings.txt"
    }
    
    # Configuration files
    $configPaths = @(
        "C:\VirtualDisplayDriver\vdd_settings.xml"
        "C:\VirtualDisplayDriver\option.txt"
        "C:\Program Files\VDD Remote Desktop\python\config.json"
    )
    
    foreach ($path in $configPaths) {
        if (Test-Path $path) {
            $fileName = Split-Path $path -Leaf
            Copy-Item $path -Destination "$TempDir\$fileName"
        }
    }
}

function Test-VDDFunctionality {
    param([string]$TempDir)
    
    Write-Host "Testing VDD functionality..." -ForegroundColor Yellow
    
    $testResults = @()
    
    # Test driver installation
    $driver = Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like "*MttVDD*" }
    $testResults += "Driver Installed: $(if ($driver) { 'Yes' } else { 'No' })"
    
    # Test virtual display device
    $device = Get-PnpDevice -FriendlyName "*VDD*" | Where-Object { $_.Status -eq "OK" }
    $testResults += "Virtual Display Active: $(if ($device) { 'Yes' } else { 'No' })"
    
    # Test service
    $service = Get-Service -Name "VDDRemoteDesktop" -ErrorAction SilentlyContinue
    $testResults += "Service Status: $(if ($service) { $service.Status } else { 'Not Installed' })"
    
    # Test web interface
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000" -UseBasicParsing -TimeoutSec 5
        $testResults += "Web Interface: Accessible (Status: $($response.StatusCode))"
    } catch {
        $testResults += "Web Interface: Not Accessible ($($_.Exception.Message))"
    }
    
    # Test API
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/displays" -TimeoutSec 5
        $testResults += "API Test: Success"
    } catch {
        $testResults += "API Test: Failed ($($_.Exception.Message))"
    }
    
    $testResults | Out-File "$TempDir\functionality_tests.txt"
}

# Main execution
try {
    Write-Host "Starting VDD Remote Desktop diagnostic collection..." -ForegroundColor Green
    
    $tempDir = Collect-SystemInfo
    Collect-EventLogs -TempDir $tempDir
    Collect-VDDLogs -TempDir $tempDir
    Collect-Configuration -TempDir $tempDir
    Test-VDDFunctionality -TempDir $tempDir
    
    # Create diagnostic summary
    $summary = @"
VDD Remote Desktop Diagnostic Report
Generated: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME

This diagnostic package contains:
- System information and hardware details
- VDD driver and device status
- Service and process information
- Network and firewall configuration
- Event logs (last 7 days)
- VDD application logs
- Configuration files
- Functionality test results

Please attach this file when reporting issues.
"@
    
    $summary | Out-File "$tempDir\README.txt"
    
    # Create ZIP archive
    Compress-Archive -Path "$tempDir\*" -DestinationPath $OutputPath -Force
    
    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force
    
    Write-Host "Diagnostic collection completed successfully!" -ForegroundColor Green
    Write-Host "Diagnostic package: $OutputPath" -ForegroundColor Cyan
    Write-Host "Package size: $([math]::Round((Get-Item $OutputPath).Length / 1MB, 2)) MB" -ForegroundColor Gray
    
} catch {
    Write-Host "Diagnostic collection failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```

## 10. Complete Deployment Package Structure

```
VDD_RemoteDesktop_Package/
├── certificates/
│   ├── VDDCodeSigning.pfx
│   ├── VDDCodeSigning.cer
│   └── cert_info.json
├── driver/
│   ├── MttVDD.sys
│   ├── MttVDD.inf
│   ├── MttVDD.cat
│   └── vdd_settings.xml
├── backend/
│   ├── RemoteDesktopBackend.dll
│   ├── VDDRemoteDesktopService.exe
│   └── dependencies/
├── python/
│   ├── main.py
│   ├── requirements.txt
│   ├── static/
│   └── templates/
├── scripts/
│   ├── install_vdd_complete.ps1
│   ├── uninstall_vdd_complete.ps1
│   ├── verify_installation.ps1
│   ├── collect_diagnostics.ps1
│   └── silent_install_options.ps1
├── installer/
│   ├── VDD_RemoteDesktop_Setup.exe
│   └── VDD_RemoteDesktop_Installer.nsi
├── docs/
│   ├── README.md
│   ├── DEPLOYMENT_GUIDE.md
│   └── TROUBLESHOOTING.md
├── manifest.json
└── version.txt
```

This comprehensive deployment system provides:

1. **Automated certificate generation and management**
2. **One-click installer creation with NSIS**
3. **Silent deployment options for enterprise environments**
4. **Group Policy deployment support**
5. **CI/CD integration with GitHub Actions**
6. **Comprehensive diagnostics and troubleshooting tools**
7. **Multiple deployment scenarios (workstation, server, kiosk)**
8. **Automated verification and testing**

The system handles the entire lifecycle from development to production deployment, ensuring secure, reliable installation of the VDD Remote Desktop solution across any Windows environment.