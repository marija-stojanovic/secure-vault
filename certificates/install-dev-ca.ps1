$ErrorActionPreference = "Stop"

$caCertificate = Join-Path $PSScriptRoot "secure-vault-dev-ca.crt"
if (-not (Test-Path -LiteralPath $caCertificate)) {
    throw "CA certifikat nije pronadjen. Prvo pokreni generate-dev-certificates.ps1."
}

Import-Certificate `
    -FilePath $caCertificate `
    -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null

Write-Host "Secure Vault Development CA je instaliran za trenutnog Windows korisnika."
Write-Host "Zatvori i ponovo otvori browser prije testiranja."

