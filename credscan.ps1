$postfixs = @("*.config", "*.log", "*.txt", "*.csv", "*.cnf", ".conf", "*.ini", "*.yml", "*.json", "*.xml", "*.sql")
$paths = @("C:\", "D:\")

Start-Transcript -Path .\out

Foreach ($path in $paths) {
    foreach ($postfix in $postfixs) {
        Get-ChildItem -Path $path -Filter $postfix -Recurse | Select-String -Pattern "(-----BEGIN RSA PRIVATE KEY-----|pass(w|\W).*|haslo|hasło)" | Select-String -Pattern "(Nikto)" -NotMatch
    }
}

Stop-Transcript
#C:\ProgramData\IBARD\   -----BEGIN RSA PRIVATE KEY-----|pass(w|\W).*|haslo|hasło
#^\W*<!--|^\W*#|^\W*\/\/|^\W*\/\*