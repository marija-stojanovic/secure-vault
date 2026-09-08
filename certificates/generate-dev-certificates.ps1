param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$privateDirectory = Join-Path $PSScriptRoot "private"
$workDirectory = Join-Path $PSScriptRoot ".work"
$backendTlsDirectory = Join-Path $projectRoot "backend\src\main\resources\tls"
$gatewayTlsDirectory = Join-Path $projectRoot "gateway\src\main\resources\tls"
$frontendTlsDirectory = Join-Path $projectRoot "frontend\certificates"

$caKeystore = Join-Path $privateDirectory "secure-vault-dev-ca.p12"
$caCertificate = Join-Path $PSScriptRoot "secure-vault-dev-ca.crt"
$backendKeystore = Join-Path $backendTlsDirectory "backend.p12"
$gatewayKeystore = Join-Path $gatewayTlsDirectory "gateway.p12"
$gatewayTruststore = Join-Path $gatewayTlsDirectory "gateway-truststore.p12"
$frontendKeystore = Join-Path $frontendTlsDirectory "frontend.p12"

$caPassword = "securevault"
$backendPassword = "securevault"
$gatewayPassword = "securevault"
$truststorePassword = "securevault"
$frontendPassword = "securevault"

$generatedFiles = @(
    $caKeystore,
    $caCertificate,
    $backendKeystore,
    $gatewayKeystore,
    $gatewayTruststore,
    $frontendKeystore
)

$existingFiles = $generatedFiles | Where-Object { Test-Path -LiteralPath $_ }
if ($existingFiles.Count -gt 0 -and -not $Force) {
    throw "Certifikati vec postoje. Pokreni skriptu sa -Force samo ako ih namjerno zelis regenerisati."
}

@($privateDirectory, $workDirectory, $backendTlsDirectory, $gatewayTlsDirectory, $frontendTlsDirectory) |
    ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }

if ($Force) {
    $generatedFiles | ForEach-Object {
        if (Test-Path -LiteralPath $_) {
            Remove-Item -LiteralPath $_ -Force
        }
    }
}

& keytool -genkeypair `
    -alias secure-vault-dev-ca `
    -dname "CN=Secure Vault Development CA, OU=Development, O=Secure Vault, C=BA" `
    -keyalg RSA -keysize 3072 -sigalg SHA384withRSA `
    -ext "BC=ca:true,pathlen:0" `
    -ext "KeyUsage=keyCertSign,cRLSign" `
    -validity 3650 `
    -storetype PKCS12 `
    -keystore $caKeystore `
    -storepass $caPassword `
    -keypass $caPassword `
    -noprompt

& keytool -exportcert `
    -alias secure-vault-dev-ca `
    -keystore $caKeystore `
    -storepass $caPassword `
    -rfc `
    -file $caCertificate

function New-ServiceCertificate {
    param(
        [string]$Alias,
        [string]$DisplayName,
        [string]$Keystore,
        [string]$Password
    )

    $csr = Join-Path $workDirectory "$Alias.csr"
    $signedCertificate = Join-Path $workDirectory "$Alias.crt"

    & keytool -genkeypair `
        -alias $Alias `
        -dname "CN=localhost, OU=$DisplayName, O=Secure Vault, C=BA" `
        -keyalg RSA -keysize 2048 -sigalg SHA256withRSA `
        -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" `
        -ext "KeyUsage=digitalSignature,keyEncipherment" `
        -ext "ExtendedKeyUsage=serverAuth" `
        -validity 825 `
        -storetype PKCS12 `
        -keystore $Keystore `
        -storepass $Password `
        -keypass $Password `
        -noprompt

    & keytool -certreq `
        -alias $Alias `
        -keystore $Keystore `
        -storepass $Password `
        -file $csr `
        -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1"

    & keytool -gencert `
        -alias secure-vault-dev-ca `
        -keystore $caKeystore `
        -storepass $caPassword `
        -infile $csr `
        -outfile $signedCertificate `
        -rfc `
        -validity 825 `
        -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" `
        -ext "KeyUsage=digitalSignature,keyEncipherment" `
        -ext "ExtendedKeyUsage=serverAuth"

    & keytool -importcert `
        -alias secure-vault-dev-ca `
        -keystore $Keystore `
        -storepass $Password `
        -file $caCertificate `
        -noprompt

    & keytool -importcert `
        -alias $Alias `
        -keystore $Keystore `
        -storepass $Password `
        -file $signedCertificate `
        -noprompt
}

New-ServiceCertificate -Alias "backend" -DisplayName "Backend" -Keystore $backendKeystore -Password $backendPassword
New-ServiceCertificate -Alias "gateway" -DisplayName "API Gateway" -Keystore $gatewayKeystore -Password $gatewayPassword
New-ServiceCertificate -Alias "frontend" -DisplayName "Frontend" -Keystore $frontendKeystore -Password $frontendPassword

& keytool -importcert `
    -alias secure-vault-dev-ca `
    -keystore $gatewayTruststore `
    -storetype PKCS12 `
    -storepass $truststorePassword `
    -file $caCertificate `
    -noprompt

Write-Host "Razvojni HTTPS certifikati su generisani."
Write-Host "Instaliraj javni CA certifikat u Current User Trusted Root: $caCertificate"
