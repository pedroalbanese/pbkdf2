# PBKDF2 User Interface
### PBKDF2 Function GUI in Pure TCL/TK

<div align="center">
 <img src="PBKDF2.png"</img>
</div>

## PHP compliant
```php
<?php
$password = "secret";
$salt = "somesalt";
$iterations = 512;
$keyLength = 16; // Key length in bytes
$algorithm = "sha256";

$derivedKey = hash_pbkdf2($algorithm, $password, $salt, $iterations, $keyLength, true);

// Convert derived key to hexadecimal representation
$derivedKeyHex = bin2hex($derivedKey);

echo "PBKDF2 Password Hash: $derivedKeyHex";
?>
```
## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2023 Pedro F. Albanese - ALBANESE Research Lab.
