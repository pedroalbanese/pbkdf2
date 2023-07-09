#include-once

#include <AutoItConstants.au3>
#include <StringConstants.au3>
#include <FileConstants.au3>
#include <Debug.au3>
#include <Array.au3>
#include <WinAPIMisc.au3>
#include <WinAPIMem.au3>

;================================================================================================================================
;
; CryptoNG -  Cryptography API: Next Generation (CNG)
;
; Purpose:
; These UDFs implement several of the Cryptography API: Next Generation (CNG) functions.
; CNG is the long-term replacement for the CryptoAPI. CNG is designed to be extensible
; at many levels and cryptography agnostic in behavior.
;
; Author:
; TheXman (https://www.autoitscript.com/forum/profile/23259-thexman/)
;
; Related Links:
; CNG Overview:   https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal
; CNG Reference:  https://docs.microsoft.com/en-us/windows/win32/seccng/cng-reference
;
;================================================================================================================================

;================================================================================================================================
; Modification Log
;
; 2022-11-15    v1.9.7
;               - Modified logging to write to a GUI console instead of to Notepad.
;                 This eliminates having to add Win11-specific logic since it uses
;                 a different control class name.
;               - No changes were made to CryptoNG.au3
;
; 2022-09-18    v1.9.6
;               - _CryptoNG_AES_GCM_DecryptData:  Added an explicit authorization
;                 tag length validation.
;               - Updated the _CryptoNG_AES_GCM_DecryptData help file entry to
;                 show the new @error (8) when the auth tag length is invalid.
;
; 2022-09-12    v1.9.5
;               - Added new algorithm-specific functions
;                 - _CryptoNG_AES_GCM_DecryptData
;                 - _CryptoNG_AES_GCM_EncryptData
;
;               - Added new internal functions that support the new AES GCM functions
;                 - __CryptoNG_IsAuthTagByteLengthValid
;                 - __CryptoNG_BCryptDecrypt_AES_GCM
;                 - __CryptoNG_BCryptEncrypt_AES_GCM
;
;               - Added an AES GCM example to the CryptoNG examples file.
;
;               - Added AES GCM functions to the CryptoNG UDF help file.
;
;               - Updated the supplied CryptoNG calltips and userudfs files.
;
;               - Optimized __CryptoNG_IsKeyBitLengthValid() function.
;
;               - Misc function header corrections/modifications
;
; 2022-02-22    v1.9.4
;               - Modified _CryptoNG_GenerateRandom() edit to make sure that the
;                 supplied number of bytes is a positive integer.
;
; 2021-08-14    v1.9.3
;               - Added 2 new algorithm-specific functions.
;                 - _CryptoNG_AES_ECB_EncryptData
;                 - _CryptoNG_AES_ECB_DecryptData
;               - Added an AES ECB example to the example file.
;               - Added AES ECB functions to the UDF help file.
;               - Modified helper functions to accommodate AES ECB functions.
;               - Updated the supplied calltips and userudfs files.
;               - Misc aesthetic modifications to the code
;
; 2021-06-07    v1.9.2
;               - Fixed a typo in the DllOpen for Bcrypt.dll (Thanks Argumentum)
;
; 2021-06-07    v1.9.1
;               - Removed internal __CryotNG_Startup and __CryotNG_Shutdown functions.  They were
;                 replaced with new helper functions to get & close DLL handles.
;                 - __CryptoNG_GetBcryptDllHandle
;                 - __CryptoNG_CloseBcryptDllHandle
;                 - __CryptoNG_GetNcryptDllHandle
;                 - __CryptoNG_CloseNcryptDllHandle
;               - Added a helper function to enable/disable debug messages.  It is primarily for
;                 internal use.
;                 - _CryptoNG_Debug
;               - Updated the help file to include the _CryptoNG_Debug function.
;               - Added a user.calltips.api file and a userudfs.properties file that includes
;                 entries for all of the public CryptoNG functions.
;               - Small changes to the ouput of a couple of the examples.
;               - Internal Changes
;                 - Changed __CryptoNG_BCryptDecrypt_CBC to __CryptoNG_BCryptDecrypt_With_BlockPadding
;                 - Changed __CryptoNG_BCryptEncrypt_CBC to __CryptoNG_BCryptEncrypt_With_BlockPadding
;
; 2021-04-14    v1.9.0
;               - Added helper functions to convert from binary to string and string to binary.
;                 - _CryptoNG_CryptBinaryToString
;                 - _CryptoNG_CryptStringToBinary
;               - Updated the help file to reflect the new helper functions and their constants.
;               - Added examples of the new helper functions to the CryptoNG_Examples.au3 file.
;
; 2021-04-12    v1.8.5
;               - Script-breaking change
;                 - Changed function name from _CryptoNG_CreateRSAKeyPair to _CryptoNG_RSA_CreateKeyPair to match the naming
;                   standards.
;                 - Updated the help file to reflect the name change.
;                 - Updated the CryptoNG_Examples.au3 file to reflect the name change.
;
; 2021-04-12    v1.8.0
;               - Added asymmetric (public/private key) RSA encryption/decryption functions
;                 - _CryptoNG_RSA_EncryptData
;                 - _CryptoNG_RSA_DecryptData
;                 - __CryptoNG_BCryptEncrypt_RSA (internal)
;                 - __CryptoNG_BCryptDecrypt_RSA (internal)
;                 - __CryptoNG_BcryptImportKeyPair (internal)
;               - Modified _CryptoNG_CreateRSAKeyPair to be able to select the export format (LEGACY/CryptoAPI-Compatible or RSA)
;               - Added create_legacy_rsa_key_pair_example to the example file
;               - Added rsa_public_private_key_encrypt_decrypt_data_example to the example file
;               - Updated the help file to reflect the modifications above.
;
; 2020-10-20    v1.7.0
;               - Added open/close of ncrpyt.dll to the Startup & Shutdown functions
;               - Added additional debug logging to startup & shutdown functions
;               - Corrected some function headers
;               - Added new function: _CryptoNG_EnumKeyStorageProviders
;               - Added new function: __CryptoNG_NCryptFreeBuffer
;
; 2020-07-12    v1.6.2
;               - Added additional function parameter validation to prevent the issue reported by @RTFC where passing empty
;                 strings to some functions was causing DllStructCreate failures.
;               - Reverted all DllStructGetData & DllStructSetData functions back to dot-notation.
;
; 2020-07-11    v1.6.1
;               - Reverted all dll struct gets & sets from dot-notation back to DllStructGetData & DllStructSetData.  Using
;                 dot-notation caused object initialization errors when value was set to an empty string. (Reported by RTFC)
;
; 2020-07-10    v1.6.0
;               - Added the ability to handle data that contains multi-byte characters. (Reported by RTFC)
;               - Removed all AU3CHECK warnings.
;               - Added a new example to show the encryption/decryption of strings with multi-byte characters:
;                 aes_cbc_encrypt_decrypt_multibyte_example()
;               - Added multi-byte characters to the example Word .docx so that the example script that encrypts/decrypts a file
;                 shows that it can handle multi-byte characters.
;               - The example scripts used to write their output to the console.  The Scite4AutoIt's editor does not display multi-
;                 byte characters in the message area.  So the example scripts now sends messages to notepad, which does handle
;                 multi-byte characters.  (Best to use a monospaced font in Notepad, like Consolas, so that the message formatting
;                 displays correctly)
;               - Removed a few examples whose functionality was duplicated in other example scripts.
;
; 2020-05-11    v1.5.5
;               - Changed DllStructGetData & DllStructSetData frunctions to dot-notation. (i.e $tStruct.data)
;               - Remove __CryptoNG_ConvertByteBuffer function.  It was no longer needed after some code refactoring.
;               - Add some constants and a new structure in preparation for authenticated ciphers.
;               - Refactored several DLL calls. Changed "ptr DllstructGetPtr" to "struct* $tStruct".
;
; 2020-04-20    v1.5.0
;               - Added the following algorithm specific functions:
;                 - _CryptoNG_3DES_CBC_DecryptData
;                 - _CryptoNG_3DES_CBC_DecryptFile
;                 - _CryptoNG_3DES_CBC_EncryptData
;                 - _CryptoNG_3DES_CBC_EncryptFile
;                 - _CryptoNG_AES_CBC_DecryptData
;                 - _CryptoNG_AES_CBC_DecryptFile
;                 - _CryptoNG_AES_CBC_EncryptData
;                 - _CryptoNG_AES_CBC_EncryptFile
;               - Added the following internal functions to handle block cipher encryption and decryption:
;                 - __CryptoNG_BCryptDecrypt_With_BlockPadding
;                 - __CryptoNG_BCryptEncrypt_With_BlockPadding
;               - Cleaned up some function headers.
;               - Fixed a small bug in how the size of the IV buffer was being determined when doing block cipher encryption
;                 and decryption. The length of the IV should match the algorithm's block size, not its key size.
;                 NOTE: The bug did NOT affect the accuracy of the results, just the size of the buffer.
;               - Corrected $CNG_KEY_BIT_LENGTH_3DES constant value.  The value was changed from 168 to 192.  168 was the
;                 usable/logical bit length but the actual bit length is 192.
;
; 2020-04-03    v1.4.0
;               - Added a Help file that includes all of the functions, with examples.  The look & feel of the
;                 new help file matches the AutoIt help files.
;               - Cleaned up several of the function headers.
;               - Added logic to _CryptoNG_DecryptFile to create the output file's path if it doesn't exist.
;               - Added logic to _CryptoNG_EncryptFile to create the output file's path if it doesn't exist.
;
; 2020-02-24    v1.3.0
;               - Added _CryptoNG_GenerateRandom and supporting internal function.  (Suggested by PeterPE)
;
; 2020-01-25    v1.2.0
;               - Added _CryptoNG_CreateRSAKeyPair and supporting internal functions, constants, and structures.
;                 (Suggested by Network_Guy)
;
; 2019-12-03    v1.1.1
;               - Corrected the _CryptoNG_PBKDF2 function header.  The syntax line was using the syntax for the
;                 _CryptoNG_HashData function.
;               - Changed variable name in the _CryptoNG_PBKDF2 function from $iKeyBitLength to $iDKeyBitLength
;                 to more aptly describe its meaning, desired key bit length.
;
; 2019-12-02    v1.1.0
;               - Cleaned up the __CryptoNG_Startup & __CryptoNG_Shutdown functions. (Suggested by argumentum)
;               - Added the abiliity to specify a desired algorithm provider when encrypting, decrypting, hashing, or using the
;                 PBKDF2 function. (Suggested by mLipok)
;
; 2019-12-01    v1.0.0
;               - Initial release
;
;================================================================================================================================

; #INDEX# =======================================================================================================================
; Title .........: CryptoNG -  Cryptography API: Next Generation (CNG)
; AutoIt Version : 3.3.14.5
; Language ......: English
; Description ...: Implementation of Microsoft's Cryptograhy: Next Gen (CNG) functions for encrypting and hashing data.
; Author(s) .....: TheXman (https://www.autoitscript.com/forum/profile/23259-thexman/)
; Dll(s) ........: bcrypt.dll, ncrypt.dll, crypt32.dll
; ===============================================================================================================================

; #CURRENT# =====================================================================================================================
; _CryptoNG_3DES_CBC_DecryptData($xData, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_3DES_CBC_DecryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_3DES_CBC_EncryptData($sText, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_3DES_CBC_EncryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_AES_CBC_DecryptData($xData, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_AES_CBC_DecryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_AES_CBC_EncryptData($sText, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_AES_CBC_EncryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; _CryptoNG_AES_ECB_DecryptData($xData, $vEncryptionKey, $sProvider = Default)
; _CryptoNG_AES_ECB_EncryptData($sText, $vEncryptionKey, $sProvider = Default)
; _CryptoNG_AES_GCM_DecryptData($xData, $vEncryptionKey, $vNonce, $xAuthTag, $sProvider = Default)
; _CryptoNG_AES_GCM_EncryptData($sText, $vEncryptionKey, $vNonce, $iAuthTagBytes = Default, $sProvider = Default)
; _CryptoNG_CryptBinaryToString($xData, $iStringFormat)
; _CryptoNG_CryptStringToBinary($sData, $iStringFormat)
; _CryptoNG_Debug($bEnable = True)
; _CryptoNG_DecryptData($sAlgorithmId, $xData, $vEncryptionKey, $sProvider = Default)
; _CryptoNG_DecryptFile($sAlgorithmId, $sInputFile, $sOutputFile, $vEncryptionKey, $sProvider = Default)
; _CryptoNG_EncryptData($sAlgorithmId, $sText, $vEncryptionKey, $sProvider = Default)
; _CryptoNG_EncryptFile($sAlgorithmId, $sInputFile, $sOutputFile, $vEncryptionKey, $sProvider = Default)
; _CryptoNG_EnumAlgorithms($iAlgorithmOperations)
; _CryptoNG_EnumKeyStorageProviders()
; _CryptoNG_EnumRegisteredProviders()
; _CryptoNG_GenerateRandom($sAlgorithmId, $iNumberOfBytes, $sProvider = Default)
; _CryptoNG_HashData($sAlgorithmId, $vData, $bHMAC = False, $vHMACSecret = "", $sProvider = Default)
; _CryptoNG_HashFile($sAlgorithmId, $sFilePath, $bHMAC = False, $vHMACSecret = "", $sProvider = Default)
; _CryptoNG_LastErrorMessage()
; _CryptoNG_PBKDF2($sPassword, $vSalt, $iIterations, $iDKeyBitLength, $sHashAlgorithmId = Default, $sProvider = Default)
; _CryptoNG_RSA_CreateKeyPair($iKeyBitLength, $sPublicKeyPath, $sPrivateKeyPath, $iExportFormat = Default, $sProvider = Default)
; _CryptoNG_RSA_DecryptData($xData, $sPrivateKeyBlobFile, $iPadding = Default, $sProvider = Default)
; _CryptoNG_RSA_EncryptData($sText, $sPublicKeyBlobFile, $iPadding = Default, $sProvider = Default)
; _CryptoNG_Version()
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; __CryptoNG_BcryptCloseAlgorithmProvider($hHandle)
; __CryptoNG_BCryptCreateHash($hAlgorithmProvider, $bHMAC = False, $vHMACSecret = "")
; __CryptoNG_BCryptDecrypt($sAlgorithmId, $xData, $hEncryptionKey, $bResultIsText = True)
; __CryptoNG_BCryptDecrypt_AES_GCM($sAlgorithmId, $xData, $hEncryptionKey, $vNonce, $xAuthTag, $bResultIsText = True)
; __CryptoNG_BCryptDecrypt_RSA($sAlgorithmId, $xData, $hEncryptionKey, $iPadding, $bResultIsText = True)
; __CryptoNG_BCryptDecrypt_With_BlockPadding($sAlgorithmId, $xData, $hEncryptionKey, $vIV = "", $bResultIsText = True)
; __CryptoNG_BCryptDeriveKeyPBKDF2($hAlgorithmProvider, $sPassword, $vSalt, $iIterations, $iKeyBitLength)
; __CryptoNG_BcryptDestroyHash($hHandle)
; __CryptoNG_BcryptDestroyKey($hKey)
; __CryptoNG_BCryptEncrypt($sAlgorithmId, $vData, $hEncryptionKey)
; __CryptoNG_BCryptEncrypt_AES_GCM($sAlgorithmId, $vData, $hEncryptionKey, $vNonce, $iAuthTagBytes)
; __CryptoNG_BCryptEncrypt_RSA($sAlgorithmId, $vData, $hEncryptionKey, $iPadding)
; __CryptoNG_BCryptEncrypt_With_BlockPadding($sAlgorithmId, $vData, $hEncryptionKey, $vIV = "")
; __CryptoNG_BcryptExportKey($hKeyPair, $sKeyBlobType)
; __CryptoNG_BCryptFinalizeKeyPair($hKeyPair)
; __CryptoNG_BCryptFinishHash($hHashObject)
; __CryptoNG_BCryptFreeBuffer($iPointer)
; __CryptoNG_BCryptGenerateKeyPair($hAlgorithmProvider, $iKeyBitLength)
; __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vSecret)
; __CryptoNG_BCryptGenRandom($hAlgorithmProvider, $iNumberOfBytes)
; __CryptoNG_BCryptGetProperty($hObject, $sProperty)
; __CryptoNG_BCryptHashData($hHashObject, $vData)
; __CryptoNG_BcryptImportKeyPair($hAlgorithmProvider, $sKeyBlobFile, $sKeyBlobType)
; __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider = "Microsoft Primitive Provider")
; __CryptoNG_BCryptOpenHashAlgorithmProvider($sAlgorithmId, $bHMAC = False, $sProvider = "Microsoft Primitive Provider")
; __CryptoNG_BCryptSetProperty($hObject, $sProperty, $vValue)
; __CryptoNG_CloseBcryptDllHandle()
; __CryptoNG_CloseNcryptDllHandle()
; __CryptoNG_DllCallErrorMessage($iError)
; __CryptoNG_GetBcryptDllHandle()
; __CryptoNG_GetNcryptDllHandle()
; __CryptoNG_IsAuthTagByteLengthValid($hAlgorithmProvider, $iAuthTagBytes)
; __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey)
; __CryptoNG_NCryptFreeBuffer($iPointer)
; __CryptoNG_StatusMessage($iStatusCode)
; ===============================================================================================================================

;CryptoNG Version Constant
Global Const $CNG_VERSION = "1.9.7"

;HASHALGORITHM_ENUM Enumeration (Used by the BCRYPT_DSA_KEY_BLOB_V2 and BCRYPT_DSA_PARAMETER_HEADER_V2 structures.)
Global Enum $CNG_DSA_HASH_ALGORITHM_SHA1, _
            $CNG_DSA_HASH_ALGORITHM_SHA256, _
			$CNG_DSA_HASH_ALGORITHM_SHA512

;BCRYPT_HASH_OPERATION_TYPE Enumeration
Global Enum $CNG_BCRYPT_HASH_OPERATION_HASH_DATA, _
			$CNG_BCRYPT_HASH_OPERATION_FINISH_HASH

;BCRYPT_MULTI_OPERATION_TYPE Enumeration
Global Enum $CNG_BCRYPT_OPERATION_TYPE_HASH

;Key Bit Lengths
Global Const $CNG_KEY_BIT_LENGTH_AES_128  = 128, _
             $CNG_KEY_BIT_LENGTH_AES_192  = 192, _
             $CNG_KEY_BIT_LENGTH_AES_256  = 256, _
             $CNG_KEY_BIT_LENGTH_DES      = 64, _
             $CNG_KEY_BIT_LENGTH_3DES     = 192, _
             $CNG_KEY_BIT_LENGTH_3DES_112 = 128, _
             $CNG_KEY_BIT_LENGTH_RC2_128  = 128, _  ;RC2 bit length can be anything between 40 and 128 in increments of 8
             $CNG_KEY_BIT_LENGTH_RC4_128  = 128, _  ;RC4 bit length can be anything between 40 and 512 in increments of 8
             $CNG_KEY_BIT_LENGTH_RC4_192  = 192, _
             $CNG_KEY_BIT_LENGTH_RC4_256  = 256, _
             $CNG_KEY_BIT_LENGTH_RC4_512  = 512

;Block Cipher Block Bit Lengths
Global Const $CNG_BLOCK_BIT_LENGTH_AES   = 128, _
             $CNG_BLOCK_BIT_LENGTH_DES   = 64, _
             $CNG_BLOCK_BIT_LENGTH_3DES  = 64

;Global Status Constants (Win32API HRESULT Values)
;https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3-3918024b10b8
Global Const $NTE_BAD_FLAGS                = 0x80090009, _
             $NTE_BAD_DATA                 = 0x80090005, _
             $NTE_INVALID_PARAMETER        = 0x80090027, _
			 $NTE_NO_MEMORY                = 0x8009000E

;Global Status Constants (Win32API NTSTATUS Values)
;https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
Global Const $CNG_STATUS_SUCCESS           = 0x00000000, _
             $CNG_STATUS_INVALID_PARAMETER = 0xC000000D, _
			 $CNG_STATUS_NO_MEMORY         = 0xC0000017, _
			 $CNG_STATUS_BUFFER_TOO_SMALL  = 0xC0000023, _
			 $CNG_STATUS_NOT_FOUND         = 0xC0000225, _
			 $CNG_STATUS_INVALID_HANDLE    = 0xC0000008, _
			 $CNG_STATUS_DATA_ERROR        = 0xC000003E, _
			 $CNG_STATUS_NOT_SUPPORTED     = 0xC00000BB, _
			 $CNG_STATUS_AUTH_TAG_MISMATCH = 0xC000A002

;Global Algorithm Flags
Global Const $CNG_BCRYPT_BLOCK_PADDING        = 0x00000001, _
             $CNG_BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008, _
             $CNG_BCRYPT_HASH_REUSABLE_FLAG   = 0x00000020

;CNG Algorithm Identifier Constants
Global Const $CNG_BCRYPT_AES_ALGORITHM               = "AES", _        ;Symmetric Cipher Algorithms
             $CNG_BCRYPT_3DES_ALGORITHM              = "3DES", _
             $CNG_BCRYPT_3DES_112_ALGORITHM          = "3DES_112", _
			 $CNG_BCRYPT_DES_ALGORITHM               = "DES", _
			 $CNG_BCRYPT_DESX_ALGORITHM              = "DESX", _
			 $CNG_BCRYPT_RC2_ALGORITHM               = "RC2", _
			 $CNG_BCRYPT_RC4_ALGORITHM               = "RC4"

Global Const $CNG_BCRYPT_SHA1_ALGORITHM              = "SHA1", _       ;Hash Algorithms
			 $CNG_BCRYPT_SHA256_ALGORITHM            = "SHA256", _
			 $CNG_BCRYPT_SHA384_ALGORITHM            = "SHA384", _
			 $CNG_BCRYPT_SHA512_ALGORITHM            = "SHA512", _
			 $CNG_BCRYPT_MD2_ALGORITHM               = "MD2", _
			 $CNG_BCRYPT_MD4_ALGORITHM               = "MD4", _
			 $CNG_BCRYPT_MD5_ALGORITHM               = "MD5", _
			 $CNG_BCRYPT_PBKDF2_ALGORITHM            = "PBKDF2"

Global Const $CNG_BCRYPT_RSA_ALGORITHM               = "RSA"           ;Asymmetric Ciphers Algorithms

Global Const $CNG_BCRYPT_DH_ALGORITHM                = "DH", _         ;Secret Agreement Algorithms
			 $CNG_BCRYPT_ECDH_ALGORITHM              = "ECDH", _
			 $CNG_BCRYPT_ECDH_P256_ALGORITHM         = "ECDH_P256", _
			 $CNG_BCRYPT_ECDH_P384_ALGORITHM         = "ECDH_P384", _
			 $CNG_BCRYPT_ECDH_P521_ALGORITHM         = "ECDH_P521"

Global Const $CNG_BCRYPT_DSA_ALGORITHM               = "DSA", _        ;Signature Agreement Algorithms
			 $CNG_BCRYPT_ECDSA_ALGORITHM             = "ECDSA", _
			 $CNG_BCRYPT_ECDSA_P256_ALGORITHM        = "ECDSA_P256", _
			 $CNG_BCRYPT_ECDSA_P384_ALGORITHM        = "ECDSA_P384", _
			 $CNG_BCRYPT_ECDSA_P521_ALGORITHM        = "ECDSA_P521", _
			 $CNG_BCRYPT_RSA_SIGN_ALGORITHM          = "RSA_SIGN"

Global Const $CNG_BCRYPT_RNG_ALGORITHM               = "RNG", _        ;Random Number Generator Algorithms
			 $CNG_BCRYPT_RNG_DUAL_EC_ALGORITHM       = "DUALECRNG", _
			 $CNG_BCRYPT_RNG_FIPS186_DSA_ALGORITHM   = "FIPS186DSARNG"

Global Const $CNG_BCRYPT_SP800108_CTR_HMAC_ALGORITHM = "SP800_108_CTR_HMAC", _
			 $CNG_BCRYPT_SP80056A_CONCAT_ALGORITHM   = "SP800_56A_CONCAT", _
			 $CNG_BCRYPT_AES_GMAC_ALGORITHM          = "AES-GMAC", _
 			 $CNG_BCRYPT_AES_CMAC_ALGORITHM          = "AES-CMAC", _
			 $CNG_BCRYPT_XTS_AES_ALGORITHM           = "XTS-AES", _
			 $CNG_BCRYPT_CAPI_KDF_ALGORITHM          = "CAPI_KDF"

Global Const $CNG_NCRYPT_KEY_STORAGE_ALGORITHM       = "KEY_STORAGE"   ;Key Storage Algorithm


;CNG Interface Identifier Constants
Global Const $CNG_BCRYPT_CIPHER_INTERFACE                = 0x00000001, _
             $CNG_BCRYPT_HASH_INTERFACE                  = 0x00000002, _
             $CNG_BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE = 0x00000003, _
             $CNG_BCRYPT_SECRET_AGREEMENT_INTERFACE      = 0x00000004, _
             $CNG_BCRYPT_SIGNATURE_INTERFACE             = 0x00000005, _
             $CNG_BCRYPT_RNG_INTERFACE                   = 0x00000006, _
             $CNG_NCRYPT_KEY_STORAGE_INTERFACE           = 0x00010001, _
             $CNG_NCRYPT_SCHANNEL_INTERFACE              = 0x00010002, _
             $CNG_NCRYPT_SCHANNEL_SIGNATURE_INTERFACE    = 0x00010003

;Cryptography Primitive Property Identifier Constants
Global Const $CNG_BCRYPT_ALGORITHM_NAME          = "AlgorithmName", _
             $CNG_BCRYPT_AUTH_TAG_LENGTH         = "AuthTagLength", _
			 $CNG_BCRYPT_BLOCK_LENGTH            = "BlockLength", _
			 $CNG_BCRYPT_BLOCK_SIZE_LIST         = "BlockSizeList", _
			 $CNG_BCRYPT_CHAINING_MODE           = "ChainingMode", _
			 $CNG_BCRYPT_CHAIN_MODE_CBC          = "ChainingModeCBC", _
			 $CNG_BCRYPT_CHAIN_MODE_CCM          = "ChainingModeCCM", _
			 $CNG_BCRYPT_CHAIN_MODE_CFB          = "ChainingModeCFB", _
			 $CNG_BCRYPT_CHAIN_MODE_ECB          = "ChainingModeECB", _
			 $CNG_BCRYPT_CHAIN_MODE_GCM          = "ChainingModeGCM", _
			 $CNG_BCRYPT_CHAIN_MODE_NA           = "ChainingModeN/A", _
			 $CNG_BCRYPT_DH_PARAMETERS           = "DHParameters", _
			 $CNG_BCRYPT_DSA_PARAMETERS          = "DSAParameters", _
			 $CNG_BCRYPT_EFFECTIVE_KEY_LENGTH    = "EffectiveKeyLength", _
			 $CNG_BCRYPT_HASH_BLOCK_LENGTH       = "HashBlockLength", _
			 $CNG_BCRYPT_HASH_LENGTH             = "HashDigestLength", _
			 $CNG_BCRYPT_HASH_OID_LIST           = "HashOIDList", _
			 $CNG_BCRYPT_INITIALIZATION_VECTOR   = "IV", _
			 $CNG_BCRYPT_KEY_LENGTH              = "KeyLength", _
			 $CNG_BCRYPT_KEY_LENGTHS             = "KeyLengths", _
			 $CNG_BCRYPT_KEY_OBJECT_LENGTH       = "KeyObjectLength", _
			 $CNG_BCRYPT_KEY_STRENGTH            = "KeyStrength", _
			 $CNG_BCRYPT_MESSAGE_BLOCK_LENGTH    = "MessageBlockLength", _
			 $CNG_BCRYPT_MULTI_OBJECT_LENGTH     = "MultiObjectLength", _
			 $CNG_BCRYPT_OBJECT_LENGTH           = "ObjectLength", _
			 $CNG_BCRYPT_PADDING_SCHEMES         = "PaddingSchemes", _
             $CNG_BCRYPT_SUPPORTED_PAD_NONE      = 0x00000000, _
			 $CNG_BCRYPT_SUPPORTED_PAD_ROUTER    = 0x00000001, _
			 $CNG_BCRYPT_SUPPORTED_PAD_PKCS1_ENC = 0x00000002, _
			 $CNG_BCRYPT_SUPPORTED_PAD_PKCS1_SIG = 0x00000004, _
			 $CNG_BCRYPT_SUPPORTED_PAD_OAEP      = 0x00000008, _
			 $CNG_BCRYPT_SUPPORTED_PAD_PSS       = 0x00000010, _
			 $CNG_BCRYPT_PROVIDER_HANDLE         = "ProviderHandle", _
			 $CNG_BCRYPT_SIGNATURE_LENGTH        = "SignatureLength"

;Key Storage Property Identifier Constants
Global Const $CNG_NCRYPT_ALGORITHM_GROUP_PROPERTY        = "Algorithm Group", _
             $CNG_NCRYPT_RSA_ALGORITHM_GROUP             = "RSA", _
             $CNG_NCRYPT_DH_ALGORITHM_GROUP              = "DH", _
             $CNG_NCRYPT_DSA_ALGORITHM_GROUP             = "DSA", _
             $CNG_NCRYPT_ECDSA_ALGORITHM_GROUP           = "ECDSA", _
             $CNG_NCRYPT_ECDH_ALGORITHM_GROUP            = "ECDH", _
             $CNG_NCRYPT_ALGORITHM_PROPERTY              = "Algorithm Name", _
             $CNG_NCRYPT_ASSOCIATED_ECDH_KEY             = "SmartCardAssociatedECDHKey", _
             $CNG_NCRYPT_BLOCK_LENGTH_PROPERTY           = "Block Length", _
             $CNG_NCRYPT_CERTIFICATE_PROPERTY            = "SmartCardKeyCertificate", _
             $CNG_NCRYPT_DH_PARAMETERS_PROPERTY          = "DHParameters", _
             $CNG_NCRYPT_EXPORT_POLICY_PROPERTY          = "Export Policy", _
             $CNG_NCRYPT_ALLOW_EXPORT_FLAG               = 0x00000001, _
             $CNG_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG     = 0x00000002, _
             $CNG_NCRYPT_ALLOW_ARCHIVING_FLAG            = 0x00000004, _
             $CNG_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG  = 0x00000008, _
             $CNG_NCRYPT_IMPL_TYPE_PROPERTY              = "Impl Type", _
             $CNG_NCRYPT_IMPL_HARDWARE_FLAG              = 0x00000001, _
             $CNG_NCRYPT_IMPL_SOFTWARE_FLAG              = 0x00000002, _
             $CNG_NCRYPT_IMPL_REMOVABLE_FLAG             = 0x00000008, _
             $CNG_NCRYPT_IMPL_HARDWARE_RNG_FLAG          = 0x00000010, _
             $CNG_NCRYPT_KEY_TYPE_PROPERTY               = "Key Type", _
             $CNG_NCRYPT_MACHINE_KEY_FLAG                = 0x00000001, _
             $CNG_NCRYPT_KEY_USAGE_PROPERTY              = "Key Usage", _
             $CNG_NCRYPT_ALLOW_DECRYPT_FLAG              = 0x00000001, _
             $CNG_NCRYPT_ALLOW_SIGNING_FLAG              = 0x00000002, _
             $CNG_NCRYPT_ALLOW_KEY_AGREEMENT_FLAG        = 0x00000004, _
             $CNG_NCRYPT_ALLOW_ALL_USAGES                = 0x00ffffff, _
 			 $CNG_NCRYPT_LAST_MODIFIED_PROPERTY          = "Modified", _
             $CNG_NCRYPT_LENGTH_PROPERTY                 = "Length", _
             $CNG_NCRYPT_LENGTHS_PROPERTY                = "Lengths", _
             $CNG_NCRYPT_MAX_NAME_LENGTH_PROPERTY        = "Max Name Length", _
             $CNG_NCRYPT_NAME_PROPERTY                   = "Name", _
             $CNG_NCRYPT_PIN_PROMPT_PROPERTY             = "SmartCardPinPrompt", _
             $CNG_NCRYPT_PIN_PROPERTY                    = "SmartCardPin", _
             $CNG_NCRYPT_PROVIDER_HANDLE_PROPERTY        = "Provider Handle", _
             $CNG_NCRYPT_READER_PROPERTY                 = "SmartCardReader", _
             $CNG_NCRYPT_ROOT_CERTSTORE_PROPERTY         = "SmartcardRootCertStore", _
             $CNG_NCRYPT_SCARD_PIN_ID                    = "SmartCardPinId", _
             $CNG_NCRYPT_SCARD_PIN_INFO                  = "SmartCardPinInfo", _
             $CNG_NCRYPT_SECURE_PIN_PROPERTY             = "SmartCardSecurePin", _
             $CNG_NCRYPT_SECURITY_DESCR_PROPERTY         = "Security Descr", _
             $CNG_NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY = "Security Descr Support", _
             $CNG_NCRYPT_SMARTCARD_GUID_PROPERTY         = "SmartCardGuid", _
             $CNG_NCRYPT_UI_POLICY_PROPERTY              = "UI Policy", _
             $CNG_NCRYPT_UNIQUE_NAME_PROPERTY            = "Unique Name", _
             $CNG_NCRYPT_USE_CONTEXT_PROPERTY            = "Use Context", _
             $CNG_NCRYPT_USE_COUNT_ENABLED_PROPERTY      = "Enabled Use Count", _
             $CNG_NCRYPT_USE_COUNT_PROPERTY              = "Use Count", _
             $CNG_NCRYPT_USER_CERTSTORE_PROPERTY         = "SmartCardUserCertStore", _
             $CNG_NCRYPT_VERSION_PROPERTY                = "Version", _
             $CNG_NCRYPT_WINDOW_HANDLE_PROPERTY          = "HWND Handle", _
             $CNG_NCRYPT_MAX_PROPERTY_DATA               = 0x100000, _
             $CNG_NCRYPT_MAX_PROPERTY_NAME               = 64

;Algorithm Operation Type Constants
Global Const $CNG_BCRYPT_CIPHER_OPERATION                = 0x00000001, _
             $CNG_BCRYPT_HASH_OPERATION                  = 0x00000002, _
			 $CNG_BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004, _
			 $CNG_BCRYPT_SECRET_AGREEMENT_OPERATION      = 0x00000008, _
			 $CNG_BCRYPT_SIGNATURE_OPERATION             = 0x00000010, _
			 $CNG_BCRYPT_RNG_OPERATION                   = 0x00000020

;RSA Symmetric Key Constants
Global Const $CNG_BCRYPT_RSAPUBLIC_BLOB        = "RSAPUBLICBLOB", _
             $CNG_BCRYPT_RSAPRIVATE_BLOB       = "RSAPRIVATEBLOB", _
             $CNG_BCRYPT_RSAFULLPRIVATE_BLOB   = "RSAFULLPRIVATEBLOB", _
             $CNG_LEGACY_RSAPUBLIC_BLOB        = "CAPIPUBLICBLOB", _
             $CNG_LEGACY_RSAPRIVATE_BLOB       = "CAPIPRIVATEBLOB", _
             $CNG_BCRYPT_RSAPUBLIC_MAGIC       = 0x31415352, _  ;RSA1
             $CNG_BCRYPT_RSAPRIVATE_MAGIC      = 0x32415352, _  ;RSA2
             $CNG_BCRYPT_RSAFULLPRIVATE_MAGIC  = 0x33415352, _   ;RSA3
             $CNG_BCRYPT_NO_KEY_VALIDATION     = 0x00000008, _
             $CNG_BCRYPT_RSA_KEY_EXPORT_RSA    = 0x00000000, _
             $CNG_BCRYPT_RSA_KEY_EXPORT_LEGACY = 0x00000001

;Authenticated Cipher Mode Constants
Global Const $CNG_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1, _
             $CNG_BCRYPT_AUTH_MODE_NONE                         = 0x00000000, _
             $CNG_BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG             = 0x00000001, _
             $CNG_BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG             = 0x00000002

;Key Storage Provider Constants
Global Const $CNG_MS_KEY_STORAGE_PROVIDER            = "Microsoft Software Key Storage Provider", _
             $CNG_MS_SMART_CARD_KEY_STORAGE_PROVIDER = "Microsoft Smart Card Key Storage Provider", _
             $CNG_MS_PLATFORM_CRYPTO_PROVIDER        = "Microsoft Platform Crypto Provider"

;CryptBinaryToString / CryptStringToBinary Constants
Global Const $CNG_CRYPT_STRING_BASE64HEADER        = 0x00000000, _ ;Base64, with BEGIN / END CERTIFICATE headers.
             $CNG_CRYPT_STRING_BASE64              = 0x00000001, _ ;Base64, without headers.
             $CNG_CRYPT_STRING_BINARY              = 0x00000002, _ ;Pure binary copy.
             $CNG_CRYPT_STRING_BASE64REQUESTHEADER = 0x00000003, _ ;Base64,  with BEGIN / END CERTIFICATE REQUEST headers.
             $CNG_CRYPT_STRING_HEX                 = 0x00000004, _ ;Hexadecimal only.
             $CNG_CRYPT_STRING_HEXASCII            = 0x00000005, _ ;Hexadecimal, with ASCII character display.
             $CNG_CRYPT_STRING_BASE64_ANY          = 0x00000006, _ ;(CryptStringToBinary Only) Tries the following, in order: BASE64HEADER, BASE64
             $CNG_CRYPT_STRING_ANY                 = 0x00000007, _ ;(CryptStringToBinary Only) Tries the following, in order: BASE64HEADER, BASE64, BINARY
             $CNG_CRYPT_STRING_HEX_ANY             = 0x00000008, _ ;(CryptStringToBinary Only) Tries the following, in order: HEXADDR, HEXASCIIADDR, HEX, HEXRAW, HEXASCII
             $CNG_CRYPT_STRING_BASE64X509CRLHEADER = 0x00000009, _ ;Base64, with X.509 CRL beginning and ending headers.
             $CNG_CRYPT_STRING_HEXADDR             = 0x0000000a, _ ;Hexadecimal, with address display.
             $CNG_CRYPT_STRING_HEXASCIIADDR        = 0x0000000b, _ ;Hexadecimal, with ASCII character and address display.
             $CNG_CRYPT_STRING_HEXRAW              = 0x0000000c, _ ;A raw hexadecimal string.
             $CNG_CRYPT_STRING_STRICT              = 0x20000000    ;Enforce strict decoding of ASN.1 text formats. Some ASN.1 binary BLOBS can have the first few bytes of the BLOB incorrectly interpreted as Base64 text. In this case, the rest of the text is ignored. Use this flag to enforce complete decoding of the BLOB.
             ;One of the following modifiers can be added to values above
Global Const $CNG_CRYPT_STRING_NOCRLF              = 0x40000000, _ ;(CryptBinaryToString Only) Do not append any new line characters to the encoded string.
             $CNG_CRYPT_STRING_NOCR                = 0x80000000    ;(CryptBinaryToString Only) Use only LF

;Global Flags
Global $__gbDebugging = False

;Global Handles
Global $__ghBcryptDll = -1
Global $__ghNcryptDll = -1

;Global Strings
Global $__gsLastErrorMessage = ""

;Global Structure Definitions
Global $__gtagRSA_KEY_BLOB = _
       "ulong Magic;"       & _
       "ulong BitLength;"   & _
       "ulong cbPublicExp;" & _
       "ulong cbModulus;"   & _
       "ulong cbPrime1;"    & _
       "ulong cbPrime2"

Global $__gtagBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO = _
       "ulong  cbSize;"        & _
       "ulong  dwInfoVersion;" & _
       "ptr    pbNonce;"       & _
       "ulong  cbNonce;"       & _
       "ptr    pbAuthData;"    & _
       "ulong  cbAuthData;"    & _
       "ptr    pbTag;"         & _
       "ulong  cbTag;"         & _
       "ptr    pbMacContext;"  & _
       "ulong  cbMacContext;"  & _
       "ulong  cbAAD;"         & _
       "uint64 cbData;"        & _
       "ulong  dwFlags;"

Global $__gtagBCRYPT_KEY_LENGTHS_STRUCT = _
       "ulong  dwMinLength;"  & _
       "ulong  dwMaxLength;"  & _
       "ulong  dwIncrement;"

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_3DES_CBC_DecryptData
; Description ...: Decrypt data using 3DES with CBC block chaining.
; Syntax ........: _CryptoNG_DecryptData($xData, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $xData               Binary data to be decrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 64 bit (8 byte) initialization vector. Default is 0x0001020304050607
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The decrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Unable to calculate key length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chaining mode
;                                       6 - Unable to decrypt data
;                                       7 - Invalid IV length
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_3DES_CBC_DecryptData($xData, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_3DES_CBC_DecryptData()")

	Const $3DES_BLOCK_SIZE_BYTES = 8

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sDecryptedText = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x0001020304050607")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If BinaryLen($xData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_3DES_ALGORITHM)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_3DES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $3DES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $3DES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(7, 0, "")
	EndIf

	;Decrypt data
	$sDecryptedText = __CryptoNG_BCryptDecrypt_With_BlockPadding($CNG_BCRYPT_3DES_ALGORITHM, $xData, $hEncryptionKey, $vIV)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sDecryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_3DES_CBC_DecryptFile
; Description ...: Decrypt file using 3DES with CBC block chaining.
; Syntax ........: _CryptoNG_3DES_CBC_DecryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $sInputFile          Path of file to be decrypted.
;                  $sOutputFile         Path of decrypted file to be output.  If file exists, it will be overwritten. Path will be created if it doesn't exist.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 64 bit (8 byte) initialization vector. Default is 0x0001020304050607
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Unable to read input file
;                                      -2 - Unable to create output file
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptDecrypt failed
;                                       7 - Unable to write to ouput file
;                                       8 - Invalid IV length
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_3DES_CBC_DecryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_3DES_CBC_DecryptFile()")

	Const $3DES_BLOCK_SIZE_BYTES = 8

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1, _
		  $hInputFile         = -1, _
		  $hOutputFile        = -1

	Local $xDecryptedData = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x0001020304050607")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If file is empty
	If FileExists($sInputFile) And FileGetSize($sInputFile) = 0 Then
		$__gsLastErrorMessage = "Input file is empty"
		Return SetError(-3, 0, False)
	EndIf

	;Open files
	$hInputFile = FileOpen($sInputFile, $FO_READ + $FO_BINARY)
	If $hInputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s"', $sInputFile)
		Return SetError(-1, 0, False)
	EndIf

	If FileExists($sOutputFile) Then FileDelete($sOutputFile)
	$hOutputFile = FileOpen($sOutputFile, $FO_APPEND + $FO_BINARY + $FO_CREATEPATH)
	If $hOutputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to create "%s"', $sOutputFile)
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		Return SetError(-2, 0, False)
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_3DES_ALGORITHM, $sProvider)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		Return SetError(2, 0, False)
	EndIf

	;Set block chaining mode
	If $CNG_BCRYPT_3DES_ALGORITHM <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hInputFile         <> -1 Then FileClose($hInputFile)
			If $hOutputFile        <> -1 Then FileClose($hOutputFile)
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, False)
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_3DES_ALGORITHM
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $3DES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $3DES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(8, 0, "")
	EndIf

	;decrypt the data
	$xDecryptedData = __CryptoNG_BCryptDecrypt_With_BlockPadding($CNG_BCRYPT_3DES_ALGORITHM, FileRead($hInputFile), $hEncryptionKey, $vIV, False)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, False)
	EndIf

	;Write the decrypted data to the file
	If Not FileWrite($hOutputFile, $xDecryptedData) Then
		$__gsLastErrorMessage = "Error writing to output file."
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(7, 0, False)
	EndIf

	;Clean up
	If $hInputFile         <> -1 Then FileClose($hInputFile)
	If $hOutputFile        <> -1 Then FileClose($hOutputFile)
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_3DES_CBC_EncryptData
; Description ...: Encrypt data using 3DES with CBC block chaining.
; Syntax ........: _CryptoNG_3DES_CBC_EncryptData($sText, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $sText               Plain text to be encrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 64 bit (8 byte) initialization vector. Default is 0x0001020304050607
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The encrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
;                                       7 - Invalid IV length
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_3DES_CBC_EncryptData($sText, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_3DES_CBC_EncryptData()")

	Const $3DES_BLOCK_SIZE_BYTES = 8

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sEncryptedText = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x0001020304050607")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If $sText = "" Then
		$__gsLastErrorMessage = "Invalid parameter - Text cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_3DES_ALGORITHM, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length (" & BinaryLen($vEncryptionKey) & ") is invalid for " & $CNG_BCRYPT_3DES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $3DES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $3DES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(7, 0, "")
	EndIf

	;Encrypt data
	$sEncryptedText = __CryptoNG_BCryptEncrypt_With_BlockPadding($CNG_BCRYPT_3DES_ALGORITHM, $sText, $hEncryptionKey, $vIV)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sEncryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_3DES_CBC_EncryptFile
; Description ...: Encrypt file using 3DES with CBC block chaining.
; Syntax ........: _CryptoNG_3DES_CBC_EncryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $sInputFile          Path of file to be encrypted.
;                  $sOutputFile         Path of encrypted file to be output.  If file exists, it will be overwritten.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 64 bit (8 byte) initialization vector. Default is 0x0001020304050607
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Unable to read input file
;                                      -2 - Unable to create output file
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
;                                       7 - Unable to write to ouput file
;                                       8 - Invalid IV length
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_3DES_CBC_EncryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_3DES_CBC_EncryptFile()")

	Const $3DES_BLOCK_SIZE_BYTES = 8

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1, _
		  $hInputFile         = -1, _
		  $hOutputFile        = -1

	Local $xEncryptedData = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x0001020304050607")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If file is empty
	If FileExists($sInputFile) And FileGetSize($sInputFile) = 0 Then
		$__gsLastErrorMessage = "Input file is empty"
		Return SetError(-3, 0, False)
	EndIf

	;Open files
	$hInputFile = FileOpen($sInputFile, $FO_READ + $FO_BINARY)
	If $hInputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s"', $sInputFile)
		Return SetError(-1, 0, False)
	EndIf

	If FileExists($sOutputFile) Then FileDelete($sOutputFile)
	$hOutputFile = FileOpen($sOutputFile, $FO_APPEND + $FO_BINARY + $FO_CREATEPATH)
	If $hOutputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to create "%s"', $sOutputFile)
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		Return SetError(-2, 0, False)
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_3DES_ALGORITHM, $sProvider)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		Return SetError(2, 0, False)
	EndIf

	;Set block chaining mode
	If $CNG_BCRYPT_3DES_ALGORITHM <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hInputFile         <> -1 Then FileClose($hInputFile)
			If $hOutputFile        <> -1 Then FileClose($hOutputFile)
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, False)
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_3DES_ALGORITHM
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $3DES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $3DES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(8, 0, "")
	EndIf

	;encrypt the data
	$xEncryptedData = __CryptoNG_BCryptEncrypt_With_BlockPadding($CNG_BCRYPT_3DES_ALGORITHM, FileRead($hInputFile), $hEncryptionKey, $vIV)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, False)
	EndIf

	;Write the encrypted data to the file
	If Not FileWrite($hOutputFile, $xEncryptedData) Then
		$__gsLastErrorMessage = "Error writing to output file."
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(7, 0, False)
	EndIf

	;Clean up
	If $hInputFile         <> -1 Then FileClose($hInputFile)
	If $hOutputFile        <> -1 Then FileClose($hOutputFile)
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_CBC_DecryptData
; Description ...: Decrypt data using AES with CBC block chaining.
; Syntax ........: _CryptoNG_DecryptData($xData, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $xData               Binary data to be decrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 128 bit (16 byte) initialization vector. Default is 0x000102030405060708090A0B0C0D0E0F
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The decrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Unable to calculate key length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chaining mode
;                                       6 - Unable to decrypt data
;                                       7 - Invalid IV length (must be 16 bytes)
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_CBC_DecryptData($xData, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_CBC_DecryptData()")

	Const $AES_BLOCK_SIZE_BYTES = 16

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sDecryptedText = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x000102030405060708090A0B0C0D0E0F")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If BinaryLen($xData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $AES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $AES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(7, 0, "")
	EndIf

	;Decrypt data
	$sDecryptedText = __CryptoNG_BCryptDecrypt_With_BlockPadding($CNG_BCRYPT_AES_ALGORITHM, $xData, $hEncryptionKey, $vIV)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sDecryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_CBC_DecryptFile
; Description ...: Decrypt file using AES with CBC block chaining.
; Syntax ........: _CryptoNG_AES_CBC_DecryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $sInputFile          Path of file to be decrypted.
;                  $sOutputFile         Path of decrypted file to be output.  If file exists, it will be overwritten. Path will be created if it doesn't exist.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 128 bit (16 byte) initialization vector. Default is 0x000102030405060708090A0B0C0D0E0F
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Unable to read input file
;                                      -2 - Unable to create output file
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptDecrypt failed
;                                       7 - Unable to write to ouput file
;                                       8 - Invalid IV length (must be 16 bytes)
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_CBC_DecryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_CBC_DecryptFile()")

	Const $AES_BLOCK_SIZE_BYTES = 16

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1, _
		  $hInputFile         = -1, _
		  $hOutputFile        = -1

	Local $xDecryptedData = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x000102030405060708090A0B0C0D0E0F")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If file is empty
	If FileExists($sInputFile) And FileGetSize($sInputFile) = 0 Then
		$__gsLastErrorMessage = "Input file is empty"
		Return SetError(-3, 0, False)
	EndIf

	;Open files
	$hInputFile = FileOpen($sInputFile, $FO_READ + $FO_BINARY)
	If $hInputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s"', $sInputFile)
		Return SetError(-1, 0, False)
	EndIf

	If FileExists($sOutputFile) Then FileDelete($sOutputFile)
	$hOutputFile = FileOpen($sOutputFile, $FO_APPEND + $FO_BINARY + $FO_CREATEPATH)
	If $hOutputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to create "%s"', $sOutputFile)
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		Return SetError(-2, 0, False)
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM, $sProvider)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		Return SetError(2, 0, False)
	EndIf

	;Set block chaining mode
	If $CNG_BCRYPT_AES_ALGORITHM <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hInputFile         <> -1 Then FileClose($hInputFile)
			If $hOutputFile        <> -1 Then FileClose($hOutputFile)
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, False)
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $AES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $AES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(8, 0, "")
	EndIf

	;decrypt the data
	$xDecryptedData = __CryptoNG_BCryptDecrypt_With_BlockPadding($CNG_BCRYPT_AES_ALGORITHM, FileRead($hInputFile), $hEncryptionKey, $vIV, False)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, False)
	EndIf

	;Write the decrypted data to the file
	If Not FileWrite($hOutputFile, $xDecryptedData) Then
		$__gsLastErrorMessage = "Error writing to output file."
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(7, 0, False)
	EndIf

	;Clean up
	If $hInputFile         <> -1 Then FileClose($hInputFile)
	If $hOutputFile        <> -1 Then FileClose($hOutputFile)
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_CBC_EncryptData
; Description ...: Encrypt data using AES with CBC block chaining.
; Syntax ........: _CryptoNG_AES_CBC_EncryptData($sText, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $sText               Plain text to be encrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 128 bit (16 byte) initialization vector. Default is 0x000102030405060708090A0B0C0D0E0F
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The encrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
;                                       7 - Invalid IV length (must be 16 bytes)
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  Encryption algorithms use an encryption key to encrypt data.  Encryption levels are usually defined by the bit
;                  length of the encryption key.  For example, AES has 3 encryption levels, 128, 192, and 256.  The encryption
;                  key length for those encryption levels are 128, 192, and 256 bits, respectively.  The length of the encryption
;                  key has to be exact or the encryption algorithm will fail.  So it is of the utmost importance that the correct
;                  length key is passed to the function.  There are 8 bits in a byte.  So, as an example, an AES192 key needs to
;                  be 192 bits (24 bytes) long.  It doesn't matter whether the key is text or binary.  All that matters is that
;                  the binary length is the correct size for the algorithm.  The easiest way to create the correct size key for a
;                  text-based encryption key, is to use the _CryptoNG_PBKDF2 function to hash it to the desired length.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_CBC_EncryptData($sText, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_CBC_EncryptData()")

	Const $AES_BLOCK_SIZE_BYTES = 16

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sEncryptedText = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x000102030405060708090A0B0C0D0E0F")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that text is not blank
	If $sText = "" Then
		$__gsLastErrorMessage = "Invalid parameter - Text cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $AES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $AES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(7, 0, "")
	EndIf

	;Encrypt data
	$sEncryptedText = __CryptoNG_BCryptEncrypt_With_BlockPadding($CNG_BCRYPT_AES_ALGORITHM, $sText, $hEncryptionKey, $vIV)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sEncryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_CBC_EncryptFile
; Description ...: Encrypt file using AES with CBC block chaining.
; Syntax ........: _CryptoNG_AES_CBC_EncryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)
; Parameters ....: $sInputFile          Path of file to be encrypted.
;                  $sOutputFile         Path of encrypted file to be output.  If file exists, it will be overwritten.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vIV                 [optional] A 128 bit (16 byte) initialization vector. Default is 0x000102030405060708090A0B0C0D0E0F
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Unable to read input file
;                                      -2 - Unable to create output file
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
;                                       7 - Unable to write to ouput file
;                                       8 - Invalid IV length (must be 16 bytes)
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $CNG_BCRYPT_AES_ALGORITHM values.
;                  Encryption algorithms use an encryption key to encrypt data.  Encryption levels are usually defined by the bit
;                  length of the encryption key.  For example, AES has 3 encryption levels, 128, 192, and 256.  The encryption
;                  key for those encryption levels are 128, 192, and 256, respectively.  The length of the encryption key has to
;                  exact are the encryption algorithm will fail.  So it is of the utmost importance that the correct length key
;                  is passed to the function.  There are 8 bits in a byte.  So, as an example, an AES192 key needs to be 24 bytes
;                  long.  It doesn't matter whether the ky is text or binary.  All that matters is that the binary length is
;                  the correct size for the algorithm.  The easiest way to create the correct size key for a text-based
;                  encryption key, is to use the _CryptoNG_PBKDF2 function to has it to the desired length.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_CBC_EncryptFile($sInputFile, $sOutputFile, $vEncryptionKey, $vIV = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_CBC_EncryptFile()")

	Const $AES_BLOCK_SIZE_BYTES = 16

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1, _
		  $hInputFile         = -1, _
		  $hOutputFile        = -1

	Local $xEncryptedData = ""


	;Resolve defaults
	If $vIV       = Default Then $vIV       = Binary("0x000102030405060708090A0B0C0D0E0F")
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If file is empty
	If FileExists($sInputFile) And FileGetSize($sInputFile) = 0 Then
		$__gsLastErrorMessage = "Input file is empty"
		Return SetError(-3, 0, False)
	EndIf

	;Open files
	$hInputFile = FileOpen($sInputFile, $FO_READ + $FO_BINARY)
	If $hInputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s"', $sInputFile)
		Return SetError(-1, 0, False)
	EndIf

	If FileExists($sOutputFile) Then FileDelete($sOutputFile)
	$hOutputFile = FileOpen($sOutputFile, $FO_APPEND + $FO_BINARY + $FO_CREATEPATH)
	If $hOutputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to create "%s"', $sOutputFile)
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		Return SetError(-2, 0, False)
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM, $sProvider)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		Return SetError(2, 0, False)
	EndIf

	;Set block chaining mode
	If $CNG_BCRYPT_AES_ALGORITHM <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hInputFile         <> -1 Then FileClose($hInputFile)
			If $hOutputFile        <> -1 Then FileClose($hOutputFile)
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, False)
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;Validate IV length based on the algorithm's block size
	If BinaryLen($vIV) <> $AES_BLOCK_SIZE_BYTES Then
		$__gsLastErrorMessage = "IV length is invalid.  Length should be " & $AES_BLOCK_SIZE_BYTES & " bytes."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(8, 0, "")
	EndIf

	;encrypt the data
	$xEncryptedData = __CryptoNG_BCryptEncrypt_With_BlockPadding($CNG_BCRYPT_AES_ALGORITHM, FileRead($hInputFile), $hEncryptionKey, $vIV)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, False)
	EndIf

	;Write the encrypted data to the file
	If Not FileWrite($hOutputFile, $xEncryptedData) Then
		$__gsLastErrorMessage = "Error writing to output file."
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(7, 0, False)
	EndIf

	;Clean up
	If $hInputFile         <> -1 Then FileClose($hInputFile)
	If $hOutputFile        <> -1 Then FileClose($hOutputFile)
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_ECB_DecryptData
; Description ...: Decrypt data using AES with ECB block chaining.
; Syntax ........: _CryptoNG_DecryptData($xData, $vEncryptionKey, $sProvider = Default)
; Parameters ....: $xData               Binary data to be decrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The decrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Unable to calculate key length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chaining mode
;                                       6 - Unable to decrypt data
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_ECB_DecryptData($xData, $vEncryptionKey, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_ECB_DecryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sDecryptedText = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If BinaryLen($xData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_ECB)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Decrypt data
	$sDecryptedText = __CryptoNG_BCryptDecrypt_With_BlockPadding($CNG_BCRYPT_AES_ALGORITHM, $xData, $hEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sDecryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_ECB_EncryptData
; Description ...: Encrypt data using AES with Electronic Code Book (ECB) mode.
; Syntax ........: _CryptoNG_AES_ECB_EncryptData($sText, $vEncryptionKey, $sProvider = Default)
; Parameters ....: $sText               Plain text to be encrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The encrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to ECB mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
; Author ........: TheXman
; Modified ......:
; Remarks .......: None
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_ECB_EncryptData($sText, $vEncryptionKey, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_ECB_EncryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $xEncryptedText = Binary("")


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that text is not blank
	If $sText = "" Then
		$__gsLastErrorMessage = "Invalid parameter - Text cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_ECB)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Encrypt data
	$xEncryptedText = __CryptoNG_BCryptEncrypt_With_BlockPadding($CNG_BCRYPT_AES_ALGORITHM, $sText, $hEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $xEncryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_GCM_DecryptData
; Description ...: Decrypt data using AES GCM.
; Syntax ........: _CryptoNG_AES_GCM_DecryptData($xData, $vEncryptionKey, $vNonce, $xAuthTag, $sProvider = Default)
; Parameters ....: $xData               Binary string containing the encrypted text.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vNonce              AES GCM Nonce.  The Microsoft Primitive Provider requires the length to be 12 bytes.
;                  $xAuthTag            Binary string containing the Authorization Tag.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A string containing the decrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                  @error:             -1 - Input data cannot be blank
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set gcm chain mode
;                                       6 - Call to __CryptoNG_BCryptDecrypt_AES_GCM failed
;                                       7 - Invalid nonce length (must be 12 bytes)
;                                       8 - Invalid auth tag length
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  Encryption algorithms use an encryption key to encrypt data.  Encryption levels are usually defined by the bit
;                  length of the encryption key.  For example, AES has 3 encryption levels, 128, 192, and 256.  The encryption
;                  key length for those encryption levels are 128, 192, and 256 bits, respectively.  The length of the encryption
;                  key has to be exact or the encryption algorithm will fail.  So it is of the utmost importance that the correct
;                  length key is passed to the function.  There are 8 bits in a byte.  So, as an example, an AES192 key needs to
;                  be 192 bits (24 bytes) long.  It doesn't matter whether the key is text or binary.  All that matters is that
;                  the binary length is the correct size for the algorithm.  The easiest way to create the correct size key for a
;                  text-based encryption key, is to use the _CryptoNG_PBKDF2 function to hash it to the desired length.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_GCM_DecryptData($xData, $vEncryptionKey, $vNonce, $xAuthTag, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_GCM_DecryptData()")


	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sDecryptedText = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"


	;Make sure that data is not blank
	If BinaryLen($xData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf


	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM)
	If @error Then Return SetError(2, 0, "")


	;Set gcm chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_GCM)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf


	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf


	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf


	;Validate Nonce length
	If BinaryLen($vNonce) <> 12 Then
		$__gsLastErrorMessage = "AES GCM nonce must be 12 bytes (96 bits)."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(7, 0, "")
	EndIf

	;Validate the auth tag length
	If Not __CryptoNG_IsAuthTagByteLengthValid($hAlgorithmProvider, BinaryLen($xAuthTag)) Then
		$__gsLastErrorMessage = "Authorization tag length is invalid."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(8, 0, "")
	EndIf


	;Decrypt data
	$sDecryptedText = __CryptoNG_BCryptDecrypt_AES_GCM($CNG_BCRYPT_AES_ALGORITHM, $xData, $hEncryptionKey, $vNonce, $xAuthTag)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf


	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sDecryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_AES_GCM_EncryptData
; Description ...: Encrypt data using AES with CBC block chaining.
; Syntax ........: _CryptoNG_AES_GCM_EncryptData($sText, $vEncryptionKey, $vNonce, $iAuthTagBytes = Default, $sProvider = Default)
; Parameters ....: $sText               Plain text to be encrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $vNonce              AES GCM Nonce.  The Microsoft Primitive Provider requires the length to be 12 bytes (96 bits).
;                  $iAuthTagBytes       [optional] Length of desired auth tag, in bytes.  Default is 16 (max size).
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A 1D array containing 2 values:
;                                       [0] Binary string containing the encrypted message
;                                       [1] Binary string containing the authorization tag.
;                  Failure:             "" and sets @error flag to non-zero.
;                  @error:             -1 - Text cannot be blank
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length or auth tag length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set gcm chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
;                                       7 - Invalid nonce length (must be 12 bytes)
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  Encryption algorithms use an encryption key to encrypt data.  Encryption levels are usually defined by the bit
;                  length of the encryption key.  For example, AES has 3 encryption levels, 128, 192, and 256.  The encryption
;                  key length for those encryption levels are 128, 192, and 256 bits, respectively.  The length of the encryption
;                  key has to be exact or the encryption algorithm will fail.  So it is of the utmost importance that the correct
;                  length key is passed to the function.  There are 8 bits in a byte.  So, as an example, an AES192 key needs to
;                  be 192 bits (24 bytes) long.  It doesn't matter whether the key is text or binary.  All that matters is that
;                  the binary length is the correct size for the algorithm.  The easiest way to create the correct size key for a
;                  text-based encryption key, is to use the _CryptoNG_PBKDF2 function to hash it to the desired length.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_AES_GCM_EncryptData($sText, $vEncryptionKey, $vNonce, $iAuthTagBytes = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_AES_GCM_EncryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $aCipherData[0]


	;Resolve defaults
	If $iAuthTagBytes = Default Then $iAuthTagBytes = 16
	If $sProvider     = Default Then $sProvider     = "Microsoft Primitive Provider"

	;Make sure that text is not blank
	If $sText = "" Then
		$__gsLastErrorMessage = "Invalid parameter - Text cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_AES_ALGORITHM, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Set GCM chaining mode
	__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_GCM)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(5, 0, "")
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $CNG_BCRYPT_AES_ALGORITHM
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Validate the auth tag length
	If Not __CryptoNG_IsAuthTagByteLengthValid($hAlgorithmProvider, $iAuthTagBytes) Then
		$__gsLastErrorMessage = "Authorization tag length is invalid."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Validate nonce length
	If BinaryLen($vNonce) <> 12 Then
		$__gsLastErrorMessage = "AES GCM nonce must be 12 bytes (96 bits)."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(7, 0, "")
	EndIf

	;Encrypt data
	$aCipherData = __CryptoNG_BCryptEncrypt_AES_GCM($CNG_BCRYPT_AES_ALGORITHM, $sText, $hEncryptionKey, $vNonce, $iAuthTagBytes)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $aCipherData

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_RSA_CreateKeyPair
; Description ...: Create a RSA public/private key pair.
; Syntax ........: _CryptoNG_RSA_CreateKeyPair($iKeyBitLength, $sPublicKeyPath, $sPrivateKeyPath[, $sProvider = Default])
; Parameters ....: $iKeyBitLength       Desired key length (in bits).  Must be a multiple of 64, >= 512, <= 16384.
;                  $sPublicKeyPath      File path to store public key.  File will be overwritten if it exists.
;                  $sPrivateKeyPath     File path to store private key.  File will be overwritten if it exists.
;                  $iExportFormat       An integer specifying the format of the key data.  Default is $CNG_BCRYPT_RSA_KEY_EXPORT_RSA.
;                                       Valid values:
;                                       $CNG_BCRYPT_RSA_KEY_EXPORT_RSA    (0)
;                                       $CNG_BCRYPT_RSA_KEY_EXPORT_LEGACY (1)
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True.
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Invalid key bit length
;                                       4 - Unable to generate symmetric key handle
;                                       5 - Unable to finalize key pair
;                                       6 - Error writing key file
; Author ........: TheXman
; Modified ......:
; Remarks .......: Public/Private key files contain binary key blobs as defined by Microsoft's BCryptExportKey function.  The
;                  format of the key can be either RSA or Legacy.  If you want to create keys that are compatible with utilities
;                  like OpenSSL, then create Legacy-formatted keys.  However, Microsoft CNG cannot import those keys for use in
;                  encryption/decryption functions.  If you plan to use CNG for RSA encryption/decryption, then you must specify
;                  RSA-formatted keys.
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _CryptoNG_RSA_CreateKeyPair($iKeyBitLength, $sPublicKeyPath, $sPrivateKeyPath, $iExportFormat = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_RSA_CreateKeyPair()")

	Local $hAlgorithmProvider = -1, _
	      $hKeyPair           = -1, _
		  $hFile              = -1

	Local $xKeyBlob = Binary("")


	;Resolve defaults
	If $iExportFormat = Default Then $iExportFormat = $CNG_BCRYPT_RSA_KEY_EXPORT_RSA
	If $sProvider     = Default Then $sProvider     = "Microsoft Primitive Provider"

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_RSA_ALGORITHM, $sProvider)
	If @error Then Return SetError(2, 0, False)

	;Validate the key length
	If $iKeyBitLength < 512 Or $iKeyBitLength > 16384 Or Mod($iKeyBitLength, 64) <> 0 Then
		$__gsLastErrorMessage = "The RSA key size must be greater than or equal to 512 bits, less than or equal to 16384 bits, and must be a multiple of 64."
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key pair handle
	$hKeyPair = __CryptoNG_BCryptGenerateKeyPair($hAlgorithmProvider, $iKeyBitLength)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;Finalize symmetric key pair
	__CryptoNG_BCryptFinalizeKeyPair($hKeyPair)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(5, 0, False)
	EndIf

	;Export public key
	If $iExportFormat = $CNG_BCRYPT_RSA_KEY_EXPORT_LEGACY Then
		$xKeyBlob = __CryptoNG_BcryptExportKey($hKeyPair, $CNG_LEGACY_RSAPUBLIC_BLOB)
	Else
		$xKeyBlob = __CryptoNG_BcryptExportKey($hKeyPair, $CNG_BCRYPT_RSAPUBLIC_BLOB)
	EndIf
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(5, 0, False)
	EndIf

	$hFile = FileOpen($sPublicKeyPath, BitOR($FO_BINARY, $FO_OVERWRITE, $FO_CREATEPATH))
	If $hFile = -1 Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(6, 0, False)
	EndIf
	If Not FileWrite($hFile, $xKeyBlob) Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(6, 0, False)
	EndIf
	FileClose($hFile)

	;Export private key
	If $iExportFormat = $CNG_BCRYPT_RSA_KEY_EXPORT_LEGACY Then
		$xKeyBlob = __CryptoNG_BcryptExportKey($hKeyPair, $CNG_LEGACY_RSAPRIVATE_BLOB)
	Else
		$xKeyBlob = __CryptoNG_BcryptExportKey($hKeyPair, $CNG_BCRYPT_RSAPRIVATE_BLOB)
	EndIf
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(5, 0, False)
	EndIf

	$hFile = FileOpen($sPrivateKeyPath, BitOR($FO_BINARY, $FO_OVERWRITE, $FO_CREATEPATH))
	If $hFile = -1 Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(6, 0, False)
	EndIf
	If Not FileWrite($hFile, $xKeyBlob) Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)
		Return SetError(6, 0, False)
	EndIf
	FileClose($hFile)

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hKeyPair           <> -1 Then __CryptoNG_BcryptDestroyKey($hKeyPair)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_CryptBinaryToString
; Description ...: Converts a binary string into a formatted text string.
; Syntax ........: _CryptoNG_CryptBinaryToString($xData, $iStringFormat)
; Parameters ....: $xData               Binary string to be converted.
;                  $iStringFormat       An integer specifying the output format of the string.
; Return values .: Success:             A converted, formatted, text string
;                  Failure:             An empty binary string and sets @error flag to non-zero.
;                  @error:              -1 - Data is not binary
;                                        1 - DllCall function failed
;                                        2 - Bad status code returned from function
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CryptBinaryToString / CryptStringToBinary Constants for $iStringFormat values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptbinarytostringw
; ===============================================================================================================================
Func _CryptoNG_CryptBinaryToString($xData, $iStringFormat)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_CryptBinaryToString()")

	Local $iError                 = 0, _
	      $iStatusCode            = 0, _
		  $iFormattedStringLength = 0

	Local $aResult[0]

	Local $sFormattedString = ""

	Local $tByteBuffer   = "", _
		  $tDword        = DllStructCreate("dword value;")


	;If data passed is not binary
	If VarGetType($xData) <> "Binary" Then
		$__gsLastErrorMessage = "The data's variable type was not binary."
		Return SetError(-1, 0, Binary(""))
	EndIf

	;If $xData is blank, then return blank
	If $xData = Binary("") Then Return Binary("")

	;Place binary data into a struct
	$tByteBuffer      = DllStructCreate(StringFormat("byte data[%i];", BinaryLen($xData)))
	$tByteBuffer.data = Binary($xData)

	;Call function to get size of buffer
	$aResult = DllCall("Crypt32.dll", "int", "CryptBinaryToStringW", _
					   "struct*",  $tByteBuffer, _
					   "dword",    DllStructGetSize($tByteBuffer), _
					   "dword",    $iStringFormat, _
					   "wstr",     Null, _
					   "dword*",   Null _
					   )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("CryptBinaryToString $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode            = $aResult[0]
	$iFormattedStringLength = $aResult[5]

	;Check status code from dllcall
	If $iStatusCode = 0 Then
		$__gsLastErrorMessage = "CryptBinaryToString failed.  Make sure that $iStringFormat is valid."
		Return SetError(2, 0, "")
	EndIf

	;Set string buffer length
	$tDword.value = $iFormattedStringLength


	;Call function to convert binary to string
	$aResult = DllCall("Crypt32.dll", "int", "CryptBinaryToStringW", _
					   "struct*",  $tByteBuffer, _
					   "dword",    DllStructGetSize($tByteBuffer), _
					   "dword",    $iStringFormat, _
					   "wstr",     "", _
					   "dword*",   DllStructGetPtr($tDword) _
					   )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("CryptBinaryToString $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode      = $aResult[0]
	$sFormattedString = $aResult[4]

	;Check status code from dllcall
	If $iStatusCode = 0 Then
		$__gsLastErrorMessage = "CryptBinaryToString failed.  Make sure that $iStringFormat is valid."
		Return SetError(2, 0, "")
	EndIf

	Return $sFormattedString

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_CryptStringToBinary
; Description ...: Converts a formatted text string into a binary string.
; Syntax ........: _CryptoNG_CryptStringToBinary($sData, $iStringFormat)
; Parameters ....: $sData               The formatted text string to be converted.
;                  $iStringFormat       An integer specifying the input format of the string.
; Return values .: Success:             A converted, binary string
;                  Failure:             "" and sets @error flag to non-zero.
;                  @error:              -1 - Data is not a string
;                                        1 - DllCall function failed
;                                        2 - Bad status code returned from function
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CryptBinaryToString/CryptStringToBinary Constants for $iStringFormat values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinaryw
; ===============================================================================================================================
Func _CryptoNG_CryptStringToBinary($sData, $iStringFormat)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_CryptStringToBinary()")

	Local $iError              = 0, _
	      $iStatusCode         = 0, _
		  $iBinaryStringLength = 0

	Local $aResult[0]

	Local $xData = ""

	Local $tByteBuffer   = "", _
	      $tDword        = DllStructCreate("dword value;")


	;If data passed data type is not a string
	If VarGetType($sData) <> "String" Then
		$__gsLastErrorMessage = "The data's variable type was not string."
		Return SetError(-1, 0, "")
	EndIf

	;If $xData is blank, then return blank
	If $sData = "" Then Return Binary("")

	;Call function to get size of buffer
	$aResult = DllCall("Crypt32.dll", "int", "CryptStringToBinaryW", _
					   "wstr",     $sData, _
					   "dword",    StringLen($sData), _
					   "dword",    $iStringFormat, _
					   "struct*",  Null, _
					   "dword*",   Null, _
					   "dword*",   Null, _
					   "dword*",   Null _
					   )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("CryptBinaryToString $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode         = $aResult[0]
	$iBinaryStringLength = $aResult[5]

	;Check status code from dllcall
	If $iStatusCode = 0 Then
		$__gsLastErrorMessage = "CryptStringToBinary failed.  Make sure that $iStringFormat is valid."
		Return SetError(2, 0, "")
	EndIf

	;Set string buffer length
	$tDword.value = $iBinaryStringLength

	;Place binary data into a struct
	$tByteBuffer = DllStructCreate(StringFormat("byte data[%i];", $iBinaryStringLength))

	;Call function to convert binary to string
	$aResult = DllCall("Crypt32.dll", "int", "CryptStringToBinaryW", _
					   "wstr",     $sData, _
					   "dword",    StringLen($sData), _
					   "dword",    $iStringFormat, _
					   "struct*",  $tByteBuffer, _
					   "dword*",   DllStructGetPtr($tDword), _
					   "dword*",   Null, _
					   "dword*",   Null _
					   )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("CryptStringToBinaryW $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]
	$xData       = $tByteBuffer.data

	;Check status code from dllcall
	If $iStatusCode = 0 Then
		$__gsLastErrorMessage = "CryptStringToBinaryW failed.  Make sure that $iStringFormat is valid."
		Return SetError(2, 0, "")
	EndIf

	Return $xData

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_Debug
; Description ...: Enables or disables debugging messages.
; Syntax ........: _CryptoNG_Debug([$bEnable = True])
; Parameters ....: $bEnable             [optional] A boolean value that specifies whether to enable/disable debug messages. Default is True.
; Return values .: None
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_Debug($bEnable = True)

	;If debugging requested
	If $bEnable Then

		;If debugging flag not already enabled
		If Not $__gbDebugging Then

			;Set debugging flag and enable debugging
			$__gbDebugging = True
			_DebugSetup("Untitled - Notepad", False, 5)

		EndIf

	Else ;Disable debugging

		;If debugging flag is set, then unset it
		If $__gbDebugging Then $__gbDebugging = False

	EndIf
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_DecryptData
; Description ...: Decrypt data using the specified algorithm.
; Syntax ........: _CryptoNG_DecryptData($sAlgorithmId, $xData, $vEncryptionKey, $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested encryption algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_CIPHER_OPERATION).
;                                       Common constant values:
;                                           $CNG_BCRYPT_AES_ALGORITHM    ("AES")
;                                           $CNG_BCRYPT_3DES_ALGORITHM   ("3DES")
;                                           $CNG_BCRYPT_DES_ALGORITHM    ("DES)
;                                           $CNG_BCRYPT_RC4_ALGORITHM    ("RC4")
;                  $xData               Binary data to be decrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The decrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Unable to calculate key length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chaining mode
;                                       6 - Unable to decrypt data
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_DecryptData($sAlgorithmId, $xData, $vEncryptionKey, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_DecryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sDecryptedText = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If BinaryLen($xData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	If $sAlgorithmId <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, "")
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $sAlgorithmId
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Decrypt data
	$sDecryptedText = __CryptoNG_BCryptDecrypt($sAlgorithmId, $xData, $hEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sDecryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_DecryptFile
; Description ...: Decrypt file using the specified algorithm.
; Syntax ........: _CryptoNG_DecryptFile($sAlgorithmId, $sInputFile, $sOutputFile, $vSecret, $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested encryption algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_CIPHER_OPERATION).
;                                       Common constant values:
;                                           $CNG_BCRYPT_AES_ALGORITHM    ("AES")
;                                           $CNG_BCRYPT_3DES_ALGORITHM   ("3DES")
;                                           $CNG_BCRYPT_DES_ALGORITHM    ("DES)
;                                           $CNG_BCRYPT_RC4_ALGORITHM    ("RC4")
;                  $sInputFile          Path of file to be decrypted.
;                  $sOutputFile         Path of decrypted file to be output.  If file exists, it will be overwritten. Path will be created if it doesn't exist.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Unable to read input file
;                                      -2 - Unable to create output file
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptDecrypt failed
;                                       7 - Unable to write to ouput file
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_DecryptFile($sAlgorithmId, $sInputFile, $sOutputFile, $vEncryptionKey, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_DecryptFile()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1, _
		  $hInputFile         = -1, _
		  $hOutputFile        = -1

	Local $xDecryptedData = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If file is empty
	If FileExists($sInputFile) And FileGetSize($sInputFile) = 0 Then
		$__gsLastErrorMessage = "Input file is empty"
		Return SetError(-3, 0, False)
	EndIf

	;Open files
	$hInputFile = FileOpen($sInputFile, $FO_READ + $FO_BINARY)
	If $hInputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s"', $sInputFile)
		Return SetError(-1, 0, False)
	EndIf

	If FileExists($sOutputFile) Then FileDelete($sOutputFile)
	$hOutputFile = FileOpen($sOutputFile, $FO_APPEND + $FO_BINARY + $FO_CREATEPATH)
	If $hOutputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to create "%s"', $sOutputFile)
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		Return SetError(-2, 0, False)
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		Return SetError(2, 0, False)
	EndIf

	;Set block chaining mode
	If $sAlgorithmId <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hInputFile         <> -1 Then FileClose($hInputFile)
			If $hOutputFile        <> -1 Then FileClose($hOutputFile)
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, False)
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $sAlgorithmId
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;decrypt the data
	$xDecryptedData = __CryptoNG_BCryptDecrypt($sAlgorithmId, FileRead($hInputFile), $hEncryptionKey, False)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, False)
	EndIf

	;Write the decrypted data to the file
	If Not FileWrite($hOutputFile, $xDecryptedData) Then
		$__gsLastErrorMessage = "Error writing to output file."
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(7, 0, False)
	EndIf

	;Clean up
	If $hInputFile         <> -1 Then FileClose($hInputFile)
	If $hOutputFile        <> -1 Then FileClose($hOutputFile)
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_EncryptData
; Description ...: Encrypt data using the specified algorithm.
; Syntax ........: _CryptoNG_EncryptData($sAlgorithmId, $sText, $vSecret, $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested encryption algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_CIPHER_OPERATION).
;                                       Common constant values:
;                                           $CNG_BCRYPT_AES_ALGORITHM    ("AES")
;                                           $CNG_BCRYPT_3DES_ALGORITHM   ("3DES")
;                                           $CNG_BCRYPT_DES_ALGORITHM    ("DES)
;                                           $CNG_BCRYPT_RC4_ALGORITHM    ("RC4")
;                  $sText               Plain text to be encrypted.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The encrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  Encryption algorithms use an encryption key to encrypt data.  Encryption levels are usually defined by the bit
;                  length of the encryption key.  For example, AES has 3 encryption levels, 128, 192, and 256.  The encryption
;                  key length for those encryption levels are 128, 192, and 256 bits, respectively.  The length of the encryption
;                  key has to be exact or the encryption algorithm will fail.  So it is of the utmost importance that the correct
;                  length key is passed to the function.  There are 8 bits in a byte.  So, as an example, an AES192 key needs to
;                  be 192 bits (24 bytes) long.  It doesn't matter whether the key is text or binary.  All that matters is that
;                  the binary length is the correct size for the algorithm.  The easiest way to create the correct size key for a
;                  text-based encryption key, is to use the _CryptoNG_PBKDF2 function to hash it to the desired length.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_EncryptData($sAlgorithmId, $sText, $vEncryptionKey, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_EncryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sEncryptedText = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If $sText = "" Then
		$__gsLastErrorMessage = "Invalid parameter - Text cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Set block chaining mode
	If $sAlgorithmId <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, "")
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $sAlgorithmId
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, "")
	EndIf

	;Encrypt data
	$sEncryptedText = __CryptoNG_BCryptEncrypt($sAlgorithmId, $sText, $hEncryptionKey)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sEncryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_EncryptFile
; Description ...: Encrypt file using the specified algorithm.
; Syntax ........: _CryptoNG_EncryptFile($sAlgorithmId, $sInputFile, $sOutputFile, $vSecret, $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested encryption algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_CIPHER_OPERATION).
;                                       Common constant values:
;                                           $CNG_BCRYPT_AES_ALGORITHM    ("AES")
;                                           $CNG_BCRYPT_3DES_ALGORITHM   ("3DES")
;                                           $CNG_BCRYPT_DES_ALGORITHM    ("DES)
;                                           $CNG_BCRYPT_RC4_ALGORITHM    ("RC4")
;                  $sInputFile          Path of file to be encrypted.
;                  $sOutputFile         Path of encrypted file to be output.  If file exists, it will be overwritten.
;                  $vEncryptionKey      Secret/Password used to encrypt text. Must be correct size for encryption algorithm.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Unable to read input file
;                                      -2 - Unable to create output file
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Invalid encryption key bit length
;                                       4 - Unable get handle to encryption key
;                                       5 - Unable to set block chain mode
;                                       6 - Call to __CryptoNG_BCryptEncrypt failed
;                                       7 - Unable to write to ouput file
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  Encryption algorithms use an encryption key to encrypt data.  Encryption levels are usually defined by the bit
;                  length of the encryption key.  For example, AES has 3 encryption levels, 128, 192, and 256.  The encryption
;                  key for those encryption levels are 128, 192, and 256, respectively.  The length of the encryption key has to
;                  exact are the encryption algorithm will fail.  So it is of the utmost importance that the correct length key
;                  is passed to the function.  There are 8 bits in a byte.  So, as an example, an AES192 key needs to be 24 bytes
;                  long.  It doesn't matter whether the ky is text or binary.  All that matters is that the binary length is
;                  the correct size for the algorithm.  The easiest way to create the correct size key for a text-based
;                  encryption key, is to use the _CryptoNG_PBKDF2 function to has it to the desired length.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_EncryptFile($sAlgorithmId, $sInputFile, $sOutputFile, $vEncryptionKey, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_EncryptFile()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1, _
		  $hInputFile         = -1, _
		  $hOutputFile        = -1

	Local $xEncryptedData = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If file is empty
	If FileExists($sInputFile) And FileGetSize($sInputFile) = 0 Then
		$__gsLastErrorMessage = "Input file is empty"
		Return SetError(-3, 0, False)
	EndIf

	;Open files
	$hInputFile = FileOpen($sInputFile, $FO_READ + $FO_BINARY)
	If $hInputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s"', $sInputFile)
		Return SetError(-1, 0, False)
	EndIf

	If FileExists($sOutputFile) Then FileDelete($sOutputFile)
	$hOutputFile = FileOpen($sOutputFile, $FO_APPEND + $FO_BINARY + $FO_CREATEPATH)
	If $hOutputFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to create "%s"', $sOutputFile)
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		Return SetError(-2, 0, False)
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		Return SetError(2, 0, False)
	EndIf

	;Set block chaining mode
	If $sAlgorithmId <> $CNG_BCRYPT_RC4_ALGORITHM Then
		__CryptoNG_BCryptSetProperty($hAlgorithmProvider, $CNG_BCRYPT_CHAINING_MODE, $CNG_BCRYPT_CHAIN_MODE_CBC)
		If @error Then
			If $hInputFile         <> -1 Then FileClose($hInputFile)
			If $hOutputFile        <> -1 Then FileClose($hOutputFile)
			If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
			Return SetError(5, 0, False)
		EndIf
	EndIf

	;Validate the key length based on the algorithm
	If Not __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey) Then
		$__gsLastErrorMessage = "Encryption key length is invalid for " & $sAlgorithmId
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, False)
	EndIf

	;Generate symmetric key handle
	$hEncryptionKey = __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(4, 0, False)
	EndIf

	;encrypt the data
	$xEncryptedData = __CryptoNG_BCryptEncrypt($sAlgorithmId, FileRead($hInputFile), $hEncryptionKey)
	If @error Then
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(6, 0, False)
	EndIf

	;Write the encrypted data to the file
	If Not FileWrite($hOutputFile, $xEncryptedData) Then
		$__gsLastErrorMessage = "Error writing to output file."
		If $hInputFile         <> -1 Then FileClose($hInputFile)
		If $hOutputFile        <> -1 Then FileClose($hOutputFile)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(7, 0, False)
	EndIf

	;Clean up
	If $hInputFile         <> -1 Then FileClose($hInputFile)
	If $hOutputFile        <> -1 Then FileClose($hOutputFile)
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return True

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_EnumAlgorithms
; Description ...: Returns an array with the available algorithms for the specified operations
; Syntax ........: _CryptoNG_EnumAlgorithms($iAlgorithmOperations)
; Parameters ....: $iAlgorithmOperations - A value that specifies the algorithm operation types to include in the enumeration.
;                                          This can be a combination of one or more values.
; Return values .: Success:                A 1D array containing the available requested algorithm operations.
;                  Failure:                An invalid array and sets @error flag to non-zero.
;                                          @extended is set to @error or status code from function that failed.
;                  @error:                 2 - BCryptEnumAlgorithms DllCall failed
;                                          3 - Bad status code returned from BCryptEnumAlgorithms
;                                          4 - BCryptFreeBuffer DllCall failed
; Author ........: TheXman
; Modified ......:
; Remarks .......: See Algorithm Operation Type Constants for algorithm operation values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumalgorithms
; ===============================================================================================================================
Func _CryptoNG_EnumAlgorithms($iAlgorithmOperations)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_EnumAlgorithms()")

	Const $tagBCRYPT_ALGORITHM_IDENTIFIER = "struct; long_ptr pszName; ulong dwClass; ulong dwFlags; endstruct"

	Local $iStructCount    = 0, _
		  $iStructPtr      = 0, _
	      $iStructArrayPtr = 0, _
		  $iStructSize     = 0, _
		  $iError          = 0, _
		  $iStatusCode     = 0

	Local $tAlgIdStruct = ""

	Local $aAlgorithOperations[0], _
	      $aResult[0]



	;Get algorithm operations
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEnumAlgorithms", _
	                   "ulong",   $iAlgorithmOperations, _
                       "ulong*",  0, _
                       "ptr*",    0, _
					   "ulong",   0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf


	;Get returned values from dllcall
	$iStatusCode     = $aResult[0]
	$iStructCount    = $aResult[2]
	$iStructArrayPtr = $aResult[3]


	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugReportVar("BCryptEnumAlgorithms $aResult", $aResult)


	;Build result array from array of structs
	$iStructSize = DllStructGetSize(DllStructCreate($tagBCRYPT_ALGORITHM_IDENTIFIER))

	For $i = 0 To $iStructCount - 1
		;Calculate pointer to next array item in the buffer and point struct to that address
		$iStructPtr   = $iStructArrayPtr + ($i * $iStructSize)
		$tAlgIdStruct = DllStructCreate($tagBCRYPT_ALGORITHM_IDENTIFIER, $iStructPtr)

		;Add algorith name to result array
		_ArrayAdd($aAlgorithOperations, _WinAPI_GetString($tAlgIdStruct.pszName))
	Next


	;Free buffer space created by BCryptEnumAlgorithms
	__CryptoNG_BCryptFreeBuffer($iStructArrayPtr)
	If @error Then Return SetError(4, @extended, "")


	;Return the result array
	Return $aAlgorithOperations

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_EnumKeyStorageProviders
; Description ...: Returns an array of registered key storage providers
; Syntax ........: _CryptoNG_EnumKeyStorageProviders()
; Parameters ....: None
; Return values .: Success:                An 1D array containing the registered key storage providers.
;                  Failure:                An invalid array and sets @error flag to non-zero.
;                                          @extended is set to @error or status code from function that failed.
;                  @error:                 2 - NCryptEnumStorageProviders DllCall failed
;                                          3 - Bad status code returned from NCryptEnumStorageProviders
;                                          4 - BCryptFreeBuffer DllCall failed
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptenumstorageproviders
; ===============================================================================================================================
Func _CryptoNG_EnumKeyStorageProviders()

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_EnumKeyStorageProviders")

	Const  $tagNCRYPT_KSP_NAME = _
	           "struct;"         & _
			   "ptr pszName;"    & _
			   "ptr pszComment;" & _
			   "endstruct;"
	Const  $NCRYPT_KSP_NAME_SIZE = DllStructGetSize($tagNCRYPT_KSP_NAME)


	Local $iItemCount         = 0, _
		  $iError             = 0, _
		  $iStatusCode        = 0, _
		  $iStructArrayPtr    = 0

	Local $pStructArrayPtr = 0

	Local $tStruct = ""

	Local $aReturnValues[0], _
	      $aResult[0]


	;Get key storage providers
	$aResult = DllCall(__CryptoNG_GetNcryptDllHandle(), "int", "NCryptEnumStorageProviders", _
                       "dword*",  0, _
                       "ptr*",    0, _
                       "dword",   0  _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf


	;Get returned values from dllcall
	$iStatusCode     = $aResult[0]
	$iItemCount      = $aResult[1]
	$pStructArrayPtr = $aResult[2]


	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugReportVar("NCryptEnumStorageProviders $aResult", $aResult)
	If $__gbDebugging Then _DebugOut("$iItemCount = " & $iItemCount)

	;Process array of structs
	For $i = 0 To $iItemCount - 1
		;Get struct array item
		$iStructArrayPtr = $pStructArrayPtr + ($i * $NCRYPT_KSP_NAME_SIZE)
		$tStruct         = DllStructCreate($tagNCRYPT_KSP_NAME, $iStructArrayPtr)

		;Load value into result array
		_ArrayAdd($aReturnValues, _WinAPI_GetString($tStruct.pszName))
	Next


	;Free buffer created by api call
	__CryptoNG_NCryptFreeBuffer($pStructArrayPtr)
	If @error Then Return SetError(4, @extended, "")


	;Return the result array
	Return $aReturnValues

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_EnumRegisteredProviders
; Description ...: Returns an array of registered CNG providers
; Syntax ........: _CryptoNG_EnumRegisteredProviders()
; Parameters ....: None
; Return values .: Success:                An 1D array containing the registered providers.
;                  Failure:                An invalid array and sets @error flag to non-zero.
;                                          @extended is set to @error or status code from function that failed.
;                  @error:                 2 - BCryptEnumRegisteredProviders DllCall failed
;                                          3 - Bad status code returned from BCryptEnumRegisteredProviders
;                                          4 - BCryptFreeBuffer DllCall failed
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumregisteredproviders
;                  https://docs.microsoft.com/windows/desktop/api/bcrypt/ns-bcrypt-crypt_providers
; ===============================================================================================================================
Func _CryptoNG_EnumRegisteredProviders()

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_EnumRegisteredProviders")

	Const $tagCRYPT_PROVIDERS = "ulong cProviders; ptr rgpszProviders"

	Local $iItemCount         = 0, _
		  $iError             = 0, _
		  $iStatusCode        = 0

	Local $pStructPtr         = 0, _
		  $pProvidersArrayPtr = 0

	Local $tStruct       = "", _
	      $tWstrPtrArray = ""

	Local $aReturnValues[0], _
	      $aResult[0]

	Local $sProvider = 0


	;Get registered providers
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEnumRegisteredProviders", _
                       "ulong*",  0, _
                       "ptr*",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf


	;Get returned values from dllcall
	$iStatusCode = $aResult[0]
	$pStructPtr  = $aResult[2]


	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugReportVar("BCryptEnumRegisteredProviders $aResult", $aResult)


	;Get return values from API
	$tStruct            = DllStructCreate($tagCRYPT_PROVIDERS, $pStructPtr)
	$iItemCount         = $tStruct.cProviders
	$pProvidersArrayPtr = $tStruct.rgpszProviders

	If $__gbDebugging Then _DebugOut("$iItemCount = " & $iItemCount)


	If $iItemCount > 0 Then
		;Build result array
		$tWstrPtrArray = DllStructCreate(StringFormat("ptr pszProviders[%i]", $iItemCount), $pProvidersArrayPtr)
		For $i = 1 To $iItemCount
			$sProvider   = _WinAPI_GetString(DllStructGetData($tWstrPtrArray, "pszProviders", $i))
			_ArrayAdd($aReturnValues, $sProvider)
		Next
	EndIf


	;Free buffer space created by api call
	__CryptoNG_BCryptFreeBuffer($pStructPtr)
	If @error Then Return SetError(4, @extended, "")


	;Return the result array
	Return $aReturnValues

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_GenerateRandom
; Description ...: Generate a specified number of randomly generated bytes.
; Syntax ........: _CryptoNG_GenerateRandom($sAlgorithmId, $iNumberOfBytes, $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested algorithm. See remarks.
;                  $iNumberOfBytes      Number of random bytes to generate.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A binary string of randomly generated bytes.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Unable get random bytes
; Author ........: TheXman
; Modified ......:
; Remarks .......: See "Random Number Generator Algorithms" global constants for named constant values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
; ===============================================================================================================================
Func _CryptoNG_GenerateRandom($sAlgorithmId, $iNumberOfBytes, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_GenerateRandom()")

	Local $hAlgorithmProvider = -1
	Local $xRandomBytes = Binary("")


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;If number of bytes is 0
	If $iNumberOfBytes < 1 Then
		$__gsLastErrorMessage = "Number of bytes must be a positive integer."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Generate random bytes
	$xRandomBytes = __CryptoNG_BCryptGenRandom($hAlgorithmProvider, $iNumberOfBytes)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)

	Return $xRandomBytes

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_HashData
; Description ...: Hash data using the specified algorithm.
; Syntax ........: _CryptoNG_HashData($sAlgorithmId, $vData, $bHMAC = False, $vHMACSecret = "", $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested hashing algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_HASH_OPERATION).
;                                       Common values:
;                                           $CNG_BCRYPT_MD5_ALGORITHM      (128 bit / 16 bytes)
;                                           $CNG_BCRYPT_SHA1_ALGORITHM     (160 bit / 20 bytes
;                                           $CNG_BCRYPT_SHA256_ALGORITHM   (256 bit / 32 bytes
;                                           $CNG_BCRYPT_SHA384_ALGORITHM   (384 bit / 48 bytes
;                                           $CNG_BCRYPT_SHA512_ALGORITHM   (512 bit / 64 bytes
;                  $vData               The data to be hashed.
;                  $bHMAC               [optional] To do a HMAC hash, set to True. Default is False.
;                  $vHMACSecret         [optional] Secret to use for HMAC hash. Default is "".
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A binary string containing the hash.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - Unable get handle to algorithm provider
;                                       3 - Unable get handle to hash object
;                                       4 - Call to hash data function failed
;                                       5 - Unable to finish hash operation
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
;                  https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
;                  https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
;                  https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
; ===============================================================================================================================
Func _CryptoNG_HashData($sAlgorithmId, $vData, $bHMAC = False, $vHMACSecret = "", $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_HashData()")

	Local $hAlgorithmProvider = -1, _
	      $hHashObject        = -1

	Local $xHash = Binary("")


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that required parameters are not blank
	If BinaryLen($vData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf
	If $bHMAC And BinaryLen($vHMACSecret) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - HMAC requested with blank HMAC Secret."
		Return SetError(-1, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenHashAlgorithmProvider($sAlgorithmId, $bHMAC, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Create hash object
	$hHashObject = __CryptoNG_BCryptCreateHash($hAlgorithmProvider, $bHMAC, $vHMACSecret)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Hash data
	__CryptoNG_BCryptHashData($hHashObject, $vData)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)
		Return SetError(4, 0, "")
	EndIf

	;Finish hash
	$xHash = __CryptoNG_BCryptFinishHash($hHashObject)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)
		Return SetError(5, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)

	Return $xHash

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_HashFile
; Description ...: Hash file contents using the specified algorithm.
; Syntax ........: _CryptoNG_HashData($sAlgorithmId, $sFilePath, $bHMAC = False, $vHMACSecret = "", $sProvider = Default)
; Parameters ....: $sAlgorithmId        A string containing the requested hashing algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_HASH_OPERATION).
;                                       Common values:
;                                       $CNG_BCRYPT_MD5_ALGORITHM
;                                       $CNG_BCRYPT_SHA1_ALGORITHM
;                                       $CNG_BCRYPT_SHA256_ALGORITHM
;                                       $CNG_BCRYPT_SHA384_ALGORITHM
;                                       $CNG_BCRYPT_SHA512_ALGORITHM
;                  $sFilePath           The file to be hashed.
;                  $bHMAC               [optional] To do a HMAC hash, set to True. Default is False.
;                  $vHMACSecret         [optional] Secret to use for HMAC hash. Default is "".
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A binary string containing the hash.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2  - Unable get handle to algorithm provider
;                                       3  - Unable get handle to hash object
;                                       4  - Call to hash data function failed
;                                       5  - Unable to finish hash operation
;                                       10 - File does not exist
;                                       11 - Unable to open file
;                                       -1 - Empty input file
;                                       -2 - HMAC requested with blank HMAC Secret
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  The file is read in 512KB chunks.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
;                  https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
;                  https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
;                  https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
; ===============================================================================================================================
Func _CryptoNG_HashFile($sAlgorithmId, $sFilePath, $bHMAC = False, $vHMACSecret = "", $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_HashFile()")

	Const $FILE_CHUNK_SIZE = 524288 ;512KB

	Local $hAlgorithmProvider = -1, _
	      $hHashObject        = -1

	Local $xHash = Binary(""), _
	      $xData = Binary("")

	Local $hFile = -1

	Local $bEOF = False

	Local $iBytesRead = 0


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Validate file's existence
	If Not FileExists($sFilePath) Then
		$__gsLastErrorMessage = StringFormat('"%s" does not exist.', $sFilePath)
		Return SetError(10, 0, "")
	EndIf

	;Make sure that required parameters are not blank or empty
	If FileGetSize($sFilePath) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Input file is empty."
		Return SetError(-1, 0, "")
	EndIf
	If $bHMAC And BinaryLen($vHMACSecret) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - HMAC requested with blank HMAC Secret."
		Return SetError(-2, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenHashAlgorithmProvider($sAlgorithmId, $bHMAC, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Create hash object
	$hHashObject = __CryptoNG_BCryptCreateHash($hAlgorithmProvider, $bHMAC, $vHMACSecret)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Open the file
	$hFile = FileOpen($sFilePath, $FO_READ + $FO_BINARY)
	If $hFile = -1 Then
		$__gsLastErrorMessage = StringFormat('Unable to open "%s".', $sFilePath)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)
		Return SetError(11, 0, "")
	EndIf

	;Hash file data
	Do
		;Read data
		$xData = FileRead($hFile, $FILE_CHUNK_SIZE)
		If @error Then $bEOF = True
		$iBytesRead = @extended

		;Hash the data
		If $iBytesRead Then
			__CryptoNG_BCryptHashData($hHashObject, $xData)
			If @error Then
				If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
				If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)
				Return SetError(4, 0, "")
			EndIf
		EndIf
	Until $bEOF

	;Close the file
	FileClose($hFile)

	;Finish hash
	$xHash = __CryptoNG_BCryptFinishHash($hHashObject)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)
		Return SetError(5, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hHashObject        <> -1 Then __CryptoNG_BcryptDestroyHash($hHashObject)

	Return $xHash

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_LastErrorMessage
; Description ...: Returns the last error message
; Syntax ........: _CryptoNG_LastErrorMessage()
; Parameters ....: None
; Return values .: None
; Author ........: TheXman
; Modified ......:
; ===============================================================================================================================
Func _CryptoNG_LastErrorMessage()
	Return $__gsLastErrorMessage
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_PBKDF2
; Description ...: Generate a Password-Based Key Derivation Function 2 key.
; Syntax ........: _CryptoNG_PBKDF2($sPassword, $vSalt, $iIterations, $iDKeyBitLength, $sHashAlgorithmId = Default, $sProvider = Default)
; Parameters ....: $sPassword           A password to derive key from.
;                  $vSalt               A salt to use for key derivation.
;                  $iIterations         Number of iteration.
;                  $iDKeyBitLength      Derived key length (in bits).  Must be a multiple of 8.
;                                       Common constant values:
;                                           $CNG_KEY_BIT_LENGTH_AES_128   (128)
;                                           $CNG_KEY_BIT_LENGTH_AES_192   (192)
;                                           $CNG_KEY_BIT_LENGTH_AES_256   (256)
;                                           $CNG_KEY_BIT_LENGTH_DES       (64)
;                                           $CNG_KEY_BIT_LENGTH_3DES      (168)
;                                           $CNG_KEY_BIT_LENGTH_RC2       (128)
;                                           $CNG_KEY_BIT_LENGTH_RC4_128   (128)
;                  $sHashAlgorithmId    [optional] HMAC hash algorithm ID Default is $CNG_BCRYPT_SHA1_ALGORITHM.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_HASH_OPERATION).
;                                       Common values:
;                                           $CNG_BCRYPT_MD5_ALGORITHM
;                                           $CNG_BCRYPT_SHA1_ALGORITHM
;                                           $CNG_BCRYPT_SHA256_ALGORITHM
;                                           $CNG_BCRYPT_SHA384_ALGORITHM
;                                           $CNG_BCRYPT_SHA512_ALGORITHM
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is "Microsoft Primitive Provider".
; Return values .: Success:             A binary string containing the key.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              -1 - Invalid parameter.  Check last error message for details.
;                                        2 - Unable get handle to algorithm provider
;                                        3 - Call to PBKDF2 function failed
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
; Related .......:
; ===============================================================================================================================
Func _CryptoNG_PBKDF2($sPassword, $vSalt, $iIterations, $iDKeyBitLength, $sHashAlgorithmId = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_PBKDF2()")

	Local $hAlgorithmProvider = -1

	Local $xKey = Binary("")


	;Validate parameters
	If Mod($iDKeyBitLength, 8) <> 0 Then
		$__gsLastErrorMessage = "Derived key length must be a multiple of 8."
		Return SetError(-1, 0, "")
	EndIf
	If $sPassword = "" Then
		$__gsLastErrorMessage = "Password cannot be blank."
		Return SetError(-1, 0, "")
	EndIf
	If BinaryLen($vSalt) = 0 Then
		$__gsLastErrorMessage = "Salt cannot be blank."
		Return SetError(-1, 0, "")
	EndIf
	If Not ($iIterations > 0) Then
		$__gsLastErrorMessage = "Number of iterations must be greater than 0."
		Return SetError(-1, 0, "")
	EndIf

	;Resolve defaults
	If $sHashAlgorithmId = Default Then $sHashAlgorithmId = $CNG_BCRYPT_SHA1_ALGORITHM
	If $sProvider        = Default Then $sProvider        = "Microsoft Primitive Provider"

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenHashAlgorithmProvider($sHashAlgorithmId, True, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Create PBKDF2 key
	$xKey = __CryptoNG_BCryptDeriveKeyPBKDF2($hAlgorithmProvider, $sPassword, $vSalt, $iIterations, $iDKeyBitLength)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)

	Return $xKey

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_RSA_DecryptData
; Description ...: Decrypt data using AES with CBC block chaining.
; Syntax ........: _CryptoNG_RSA_DecryptData($xData, $sPrivateKeyBlobFile, $iPadding = Default, $sProvider = Default)
; Parameters ....: $xData               Binary data to be decrypted.
;                  $sPrivateKeyBlobFile RSA-formatted private key blob file path.
;                  $iPadding            [optional] An integer specifying the padding routine. Default is $CNG_BCRYPT_SUPPORTED_PAD_PKCS1_ENC.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             The decrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Data to decrypt cannot be blank
;                                      -2 - Key blob file does not exist.
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Unable get handle to encryption key
;                                       4 - Unable to decrypt data
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Cryptography Primitive Property Identifier Constants for valid $iPadding values. ($CNG_BCRYPT_SUPPORTED_PAD_*)
; ===============================================================================================================================
Func _CryptoNG_RSA_DecryptData($xData, $sPrivateKeyBlobFile, $iPadding = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_RSA_DecryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $sDecryptedText = ""


	;Resolve defaults
	If $iPadding  = Default Then $iPadding  = $CNG_BCRYPT_SUPPORTED_PAD_PKCS1_ENC
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"

	;Make sure that data is not blank
	If BinaryLen($xData) = 0 Then
		$__gsLastErrorMessage = "Invalid parameter - Data cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Make sure that key blob file exists
	If Not FileExists($sPrivateKeyBlobFile) Then
		$__gsLastErrorMessage = "Private key blob file does not exist."
		Return SetError(-2, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_RSA_ALGORITHM)
	If @error Then Return SetError(2, 0, "")

	;Import rsa public key
	$hEncryptionKey = __CryptoNG_BcryptImportKeyPair($hAlgorithmProvider, $sPrivateKeyBlobFile, $CNG_BCRYPT_RSAPRIVATE_BLOB)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Decrypt data
	$sDecryptedText = __CryptoNG_BCryptDecrypt_RSA($CNG_BCRYPT_RSA_ALGORITHM, $xData, $hEncryptionKey, $iPadding)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(4, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $sDecryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_RSA_EncryptData
; Description ...: Encrypt data using RSA public key.
; Syntax ........: _CryptoNG_RSA_EncryptData($sText, $sPublicKeyBlobFile, $iPadding = Default, $sProvider = Default)
; Parameters ....: $sText               Plain text to be encrypted.
;                  $sPrivateKeyBlobFile RSA-formatted public key blob file path.
;                  $iPadding            [optional] An integer specifying the padding routine. Default is $CNG_BCRYPT_SUPPORTED_PAD_PKCS1_ENC.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             Binary encrypted text.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:             -1 - Text to be encrypted cannot be blank.
;                                      -2 - Key blob file does not exist.
;                                       2 - Unable get handle to algorithm provider
;                                       3 - Unable get handle to rsa public key
;                                       4 - Unable to encrypt data
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
;                  See CNG Cryptography Primitive Property Identifier Constants for valid $iPadding values. ($CNG_BCRYPT_SUPPORTED_PAD_*)
; Related .......: Only public key blob files that were exported using the RSA format can be used for BCRYPT encryption.
; ===============================================================================================================================
Func _CryptoNG_RSA_EncryptData($sText, $sPublicKeyBlobFile, $iPadding = Default, $sProvider = Default)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: _CryptoNG_RSA_EncryptData()")

	Local $hAlgorithmProvider = -1, _
	      $hEncryptionKey     = -1

	Local $xEncryptedText = ""


	;Resolve defaults
	If $sProvider = Default Then $sProvider = "Microsoft Primitive Provider"
	If $iPadding  = Default Then $iPadding  = $CNG_BCRYPT_SUPPORTED_PAD_PKCS1_ENC

	;Make sure that text is not blank
	If $sText = "" Then
		$__gsLastErrorMessage = "Invalid parameter - Text cannot be blank."
		Return SetError(-1, 0, "")
	EndIf

	;Make sure that key blob file exists
	If Not FileExists($sPublicKeyBlobFile) Then
		$__gsLastErrorMessage = "Public key blob file does not exist."
		Return SetError(-2, 0, "")
	EndIf

	;Open algorithm provider
	$hAlgorithmProvider = __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($CNG_BCRYPT_RSA_ALGORITHM, $sProvider)
	If @error Then Return SetError(2, 0, "")

	;Import rsa public key
	$hEncryptionKey = __CryptoNG_BcryptImportKeyPair($hAlgorithmProvider, $sPublicKeyBlobFile, $CNG_BCRYPT_RSAPUBLIC_BLOB)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(3, 0, "")
	EndIf

	;Encrypt data
	$xEncryptedText = __CryptoNG_BCryptEncrypt_RSA($CNG_BCRYPT_RSA_ALGORITHM, $sText, $hEncryptionKey, $iPadding)
	If @error Then
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)
		Return SetError(4, 0, "")
	EndIf

	;Clean up
	If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
	If $hEncryptionKey     <> -1 Then __CryptoNG_BcryptDestroyKey($hEncryptionKey)

	Return $xEncryptedText

EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _CryptoNG_Version
; Description ...: Return the UDF file's version number
; Syntax ........: _CryptoNG_Version()
; Parameters ....: None
; Return values .: A string version number.
; Author ........: TheXman
; ===============================================================================================================================
Func _CryptoNG_Version()
	Return $CNG_VERSION
EndFunc

;===================================================  INTERNAL FUNCTIONS  =======================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BcryptCloseAlgorithmProvider
; Description ...: Close handle to algorithm provider.
; Syntax ........: __CryptoNG_BcryptCloseAlgorithmProvider($hHandle)
; Parameters ....: $hHandle             Handle to algoithm provider.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
; Author ........: TheXman
; Modified ......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
; ===============================================================================================================================
Func __CryptoNG_BcryptCloseAlgorithmProvider($hHandle)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BcryptCloseAlgorithmProvider()")

	Local $iError = 0

	;Close handle
	DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptCloseAlgorithmProvider", "handle",  $hHandle, "ulong", 0)
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf

	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptCreateHash
; Description ...: Create a hash or Message Authentication Code (MAC) object.
; Syntax ........: __CryptoNG_BCryptCreateHash($sAlgorithmId, $bHMAC = False)
; Parameters ....: $hAlgorithmProvider  A handle to the open algorithm provider.
;                  $bHMAC               [optional] To do a HMAC hash, set to True. Default is False.
;                  $vHMACSecret         [optional] Secret to use for HMAC hash. Default is "".
; Return values .: Success:             A handle to the hash object.
;                  Failure:             -1 and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - HMAC requested but no HMAC secret was supplied
;                                       2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
; ===============================================================================================================================
Func __CryptoNG_BCryptCreateHash($hAlgorithmProvider, $bHMAC = False, $vHMACSecret = "")

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptCreateHash()")

	Local $aResult[0]

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $hHashObject = 0

	Local $tHMACSecretBuffer = ""

	Local $xHMACSecret = Binary("")


	;If a HMAC secret was passed,
	If $bHMAC Then
		If IsString($vHMACSecret) Then
			$xHMACSecret = StringToBinary($vHMACSecret, $SB_UTF8)
		Else
			$xHMACSecret = Binary($vHMACSecret)
		EndIf

		$tHMACSecretBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xHMACSecret)))
		$tHMACSecretBuffer.data = $xHMACSecret
	EndIf

	;Open algorithm provider
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptCreateHash", _
                       "handle",   $hAlgorithmProvider, _
                       "handle*",  0, _
                       "ptr",      Null, _
                       "ulong",    0, _
                       "struct*",  ($bHMAC) ? ($tHMACSecretBuffer) : (Null), _
                       "ulong",    ($bHMAC) ? (DllStructGetSize($tHMACSecretBuffer)) : (0), _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(2, $iError, -1)
	EndIf
	If $__gbDebugging Then _DebugOut("BCryptCreateHash $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]
	$hHashObject = $aResult[2]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, -1)
	EndIf

	;All is good, return the handle
	Return $hHashObject

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptDecrypt
; Description ...: Decrypt data
; Syntax ........: __CryptoNG_BCryptDecrypt($sAlgorithmId, $vData, $hEncryptionKey, $bResultIsText = True)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $xData               Binary data to be decrypted.
;                  $hEncryptionKey      A handle to the encryption/decryption key.
;                  $bResultIsText       [optional] A boolean value representing whether to convert the binary decrypted data
;                                       to text. Default is True.
; Return values .: Success:             Decrypted data.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - Unable to get length of key
;                                       2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: If a block cipher algorithm is requested, the generated IV will be the length of the algoritm's
;                  block size and will contain consecutive binary byte values starting from 0x00.  i.e. 0x000102...0F
;
;                  When decrypting a file, you should set $bResultIsText to false.  This will leave the result as binary, which
;                  is what is needed for file decryption.
;
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
; ===============================================================================================================================
Func __CryptoNG_BCryptDecrypt($sAlgorithmId, $xData, $hEncryptionKey, $bResultIsText = True)

	Local $tInputBuffer  = "", _
	      $tOutputBuffer = "", _
		  $tIVBuffer     = "", _
		  $tByteBuffer   = "", _
		  $tUlong        = ""

	Local $iBlockLength  = 0, _
	      $iStatusCode   = 0, _
		  $iError        = 0, _
		  $iOutputLength = 0

	Local $aResult[0]

	Local $vDecryptedData = ""

	Local $xIV = Binary("")


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptDecrypt()")

	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$xData        = " & $xData)

	;Get length of key
	$tByteBuffer = __CryptoNG_BCryptGetProperty($hEncryptionKey, $CNG_BCRYPT_KEY_LENGTH)
	If @error Then Return SetError(1, 0, "")
	$tUlong     = _WinAPI_CopyStruct($tByteBuffer, "ulong value")

	;If this is a block cipher (not a stream cipher)
	If $sAlgorithmId <> $CNG_BCRYPT_RC4_ALGORITHM Then
		;Get length of block
		$tByteBuffer = __CryptoNG_BCryptGetProperty($hEncryptionKey, $CNG_BCRYPT_BLOCK_LENGTH)
		If @error Then Return SetError(1, 0, "")
		$tUlong       = _WinAPI_CopyStruct($tByteBuffer, "ulong value")
		$iBlockLength = $tUlong.value
		If $__gbDebugging Then _DebugOut("$iBlockLength = " & $iBlockLength)

		;Create initialization vector (IV) buffer and set its default value (0x000102...)
		$xIV = Binary("")
		For $i = 0 To $iBlockLength - 1
			$xIV &= Binary(Chr($i))
		Next
		$tIVBuffer      = DllStructCreate(StringFormat("byte data[%i]", $iBlockLength))
		$tIVBuffer.data = $xIV
		If $__gbDebugging Then _DebugOut("IV = " & $tIVBuffer.data)
	EndIf

	;Create input buffer and move input to the buffer
	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = Binary($xData)

	;Get size of decrypted output
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (Null) : ($tIVBuffer), _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0)    : (DllStructGetSize($tIVBuffer)), _
                       "ptr",      Null, _
                       "ulong*",   0, _
                       "ulong*",   Null, _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0) : ($CNG_BCRYPT_BLOCK_PADDING) _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iOutputLength = $aResult[9]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Output length = " & $iOutputLength)

	;Create output buffer
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", $iOutputLength))

	;Decrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (Null) : ($tIVBuffer), _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0) : (DllStructGetSize($tIVBuffer)), _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0) : ($CNG_BCRYPT_BLOCK_PADDING) _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$vDecryptedData = BinaryMid($tOutputBuffer.data, 1, $aResult[9])

	;If the result should be text, then convert the binary result to a string
	If $bResultIsText Then $vDecryptedData = BinaryToString($vDecryptedData, $SB_UTF8)

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Decrypted data = " & $vDecryptedData)


	Return $vDecryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptDecrypt_AES_GCM
; Description ...: Decrypt data
; Syntax ........: __CryptoNG_BCryptDecrypt_AES_GCM($sAlgorithmId, $xData, $hEncryptionKey, $vNonce, $xAuthTag, $bResultIsText = True)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $xData               Binary data to be decrypted.
;                  $hEncryptionKey      A handle to the encryption/decryption key.
;                  $vNonce              AES GCM Nonce.  The Microsoft Primitive Provider requires the length to be 12 bytes.
;                  $xAuthTag            A binary string containing the Authorization Tag.
;                  $bResultIsText       [optional] A boolean value representing whether to convert the binary decrypted data
;                                       to text. Default is True.
; Return values .: Success:             Decrypted data.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - Unable to get length of key
;                                       2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: If a block cipher algorithm is requested, the generated IV will be the length of the algoritm's
;                  block size and will contain consecutive binary byte values starting from 0x00.  i.e. 0x000102...0F
;
;                  When decrypting a file, you should set $bResultIsText to false.  This will leave the result as binary, which
;                  is what is needed for file decryption.
;
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
; ===============================================================================================================================
Func __CryptoNG_BCryptDecrypt_AES_GCM($sAlgorithmId, $xData, $hEncryptionKey, $vNonce, $xAuthTag, $bResultIsText = True)

	Local $tInputBuffer   = "", _
	      $tOutputBuffer  = "", _
		  $tNonceBuffer   = "", _
		  $tAuthTagBuffer = "", _
		  $tAuthInfo      = "", _
		  $tMACBuffer     = ""

	Local $iStatusCode   = 0, _
		  $iError        = 0

	Local $aResult[0]

	Local $vDecryptedData = ""


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptDecrypt_AES_GCM()")
	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$xData        = " & $xData)
	If $__gbDebugging Then _DebugOut("$vNonce       = " & $vNonce)
	If $__gbDebugging Then _DebugOut("$xAuthTag     = " & $xAuthTag)


	;Create input buffer and move input to the buffer
	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = Binary($xData)


	;Create nonce buffer and data to it
	$tNonceBuffer      = DllStructCreate(StringFormat("byte data[%s];", BinaryLen($vNonce)))
	$tNonceBuffer.data = Binary($vNonce)


	;Create auth tag buffer and data to it
	$tAuthTagBuffer      = DllStructCreate(StringFormat("byte data[%s];", BinaryLen($xAuthTag)))
	$tAuthTagBuffer.data = Binary($xAuthTag)


	;Create other buffer
	$tMACBuffer    = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xAuthTag)))
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))


	;Create Auth Info struct and populate it
	$tAuthInfo               = DllStructCreate($__gtagBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)

	$tAuthInfo.dwInfoVersion = $CNG_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
	$tAuthInfo.cbSize        = DllStructGetSize($tAuthInfo)

	$tAuthInfo.pbNonce       = DllStructGetPtr($tNonceBuffer)
	$tAuthInfo.cbNonce       = DllStructGetSize($tNonceBuffer)

	$tAuthInfo.pbTag         = DllStructGetPtr($tAuthTagBuffer)
	$tAuthInfo.cbTag         = DllStructGetSize($tAuthTagBuffer)

	$tAuthInfo.pbMacContext  = DllStructGetPtr($tMACBuffer)
	$tAuthInfo.cbMacContext  = DllStructGetSize($tMACBuffer)


	;Decrypt data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "struct*",  $tAuthInfo, _
                       "struct*",  Null, _
                       "ulong",    0, _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)


	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$vDecryptedData = BinaryMid($tOutputBuffer.data, 1, $aResult[9])

	If $__gbDebugging Then _DebugOut("Decrypted data = " & $vDecryptedData)


	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf


	;If the result should be text, then convert the binary result to a string
	If $bResultIsText Then $vDecryptedData = BinaryToString($vDecryptedData, $SB_UTF8)


	Return $vDecryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptDecrypt_With_BlockPadding
; Description ...: Decrypt data using CBC chaining mode
; Syntax ........: __CryptoNG_BCryptDecrypt_With_BlockPadding($sAlgorithmId, $xData, $hEncryptionKey, $vIV = Default, $bResultIsText = True)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $xData               Binary data to be decrypted.
;                  $hEncryptionKey      A handle to the encryption/decryption key.
;                  $vIV                 [optional] Initialization Vector.  Default is ""
;                                       starting at 0x00 for the length block size.
;                  $bResultIsText       [optional] A boolean value representing whether to convert the binary decrypted data
;                                       to text. Default is True.
; Return values .: Success:             Decrypted data.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
;                  When decrypting a file, you should set $bResultIsText to false.  This will leave the result as binary, which
;                  is what is needed for file decryption.
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_BCryptDecrypt_With_BlockPadding($sAlgorithmId, $xData, $hEncryptionKey, $vIV = "", $bResultIsText = True)

	Local $tInputBuffer  = "", _
	      $tOutputBuffer = "", _
		  $tIVBuffer     = ""

	Local $iStatusCode   = 0, _
		  $iError        = 0, _
		  $iOutputLength = 0

	Local $aResult[0]

	Local $vDecryptedData = ""


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptDecrypt_With_BlockPadding()")

	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$xData        = " & $xData)

	;Create input buffer and move input to the buffer
	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = Binary($xData)

	;Create initialization vector (IV) buffer and set its value
	If BinaryLen($vIV) > 0 Then
		$tIVBuffer = DllStructCreate(StringFormat("byte data[%i]", BinaryLen(Binary($vIV))))
		$tIVBuffer.data = Binary($vIV)
		If $__gbDebugging Then _DebugOut("IV = " & $tIVBuffer.data)
	EndIf

	;Get size of decrypted output
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  (BinaryLen($vIV) > 0 ? $tIVBuffer : Null), _
                       "ulong",    (BinaryLen($vIV) > 0 ? DllStructGetSize($tIVBuffer) : 0), _
                       "ptr",      Null, _
                       "ulong*",   0, _
                       "ulong*",   Null, _
                       "ulong",    $CNG_BCRYPT_BLOCK_PADDING _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iOutputLength = $aResult[9]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Output length = " & $iOutputLength)

	;Create output buffer
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", $iOutputLength))

	;Decrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  (BinaryLen($vIV) > 0 ? $tIVBuffer : Null), _
                       "ulong",    (BinaryLen($vIV) > 0 ? DllStructGetSize($tIVBuffer) : 0), _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    $CNG_BCRYPT_BLOCK_PADDING _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$vDecryptedData = BinaryMid($tOutputBuffer.data, 1, $aResult[9])

	;If the result should be text, then convert the binary result to a string
	If $bResultIsText Then $vDecryptedData = BinaryToString($vDecryptedData, $SB_UTF8)

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Decrypted data = " & $vDecryptedData)


	Return $vDecryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptDecrypt_RSA
; Description ...: Decrypt data using a RSA private key.
; Syntax ........: __CryptoNG_BCryptDecrypt_RSA($sAlgorithmId, $xData, $hEncryptionKey, $iPadding, $bResultIsText = True)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $xData               Binary data to be decrypted.
;                  $hEncryptionKey      A handle to the encryption/decryption key.
;                  $iPadding            An integer specifying the padding routine to be used.
;                                       starting at 0x00 for the length block size.
;                  $bResultIsText       [optional] A boolean value representing whether to convert the binary decrypted data
;                                       to text. Default is True.
; Return values .: Success:             Decrypted data.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
;                  When decrypting a file, you should set $bResultIsText to false.  This will leave the result as binary, which
;                  is what is needed for file decryption.
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_BCryptDecrypt_RSA($sAlgorithmId, $xData, $hEncryptionKey, $iPadding, $bResultIsText = True)

	Local $tInputBuffer  = "", _
	      $tOutputBuffer = ""

	Local $iStatusCode   = 0, _
		  $iError        = 0, _
		  $iOutputLength = 0

	Local $aResult[0]

	Local $vDecryptedData = ""


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptDecrypt_RSA()")

	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$xData        = " & $xData)

	;Create input buffer and move input to the buffer
	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = Binary($xData)

	;Get size of decrypted output
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  Null, _
                       "ulong",    0, _
                       "ptr",      Null, _
                       "ulong*",   Null, _
                       "ulong*",   Null, _
                       "ulong",    $iPadding _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iOutputLength = $aResult[9]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Output length = " & $iOutputLength)

	;Create output buffer
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", $iOutputLength))

	;Decrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDecrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  Null, _
                       "ulong",    0, _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    $iPadding _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDecrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$vDecryptedData = BinaryMid($tOutputBuffer.data, 1, $aResult[9])

	;If the result should be text, then convert the binary result to a string
	If $bResultIsText Then $vDecryptedData = BinaryToString($vDecryptedData, $SB_UTF8)

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Decrypted data = " & $vDecryptedData)


	Return $vDecryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptDeriveKeyPBKDF2
; Description ...: Derive a key from a hash value by using the PBKDF2 key derivation algorithm as defined by RFC 2898
; Syntax ........: __CryptoNG_BCryptDeriveKeyPBKDF2($hAlgorithmProvider, $sPassword, $sSalt, $iIterations, $iKeyBitLength)
; Parameters ....: $hAlgorithmProvider     A handle to a algorithm provider
;                  $sPassword              A text password
;                  $vSalt                  A salt value
;                  $iIterations            Number of iterations.
;                  $iKeyBitLength          Desired key length (in bits).
; Return values .: Success:                A PBKDF2 key.
;                  Failure:                "" and sets @error flag to non-zero.
;                                          @extended is set to @error or status code from function that failed.
;                  @error:                 1 - DllCall failed
;                                          2 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2
; ===============================================================================================================================
Func __CryptoNG_BCryptDeriveKeyPBKDF2($hAlgorithmProvider, $sPassword, $vSalt, $iIterations, $iKeyBitLength)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptDeriveKeyPBKDF2()")

	Local $aResult[0]

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $tPasswordBuffer = "", _
	      $tSaltBuffer     = "", _
		  $tKeyBuffer      = ""

	Local $xKey      = Binary(""), _
	      $xPassword = Binary(""), _
	      $xSalt     = Binary("")


	;Create buffer for password and move it into the buffer
	$xPassword            = StringToBinary($sPassword, $SB_UTF8)
	$tPasswordBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xPassword)))
	$tPasswordBuffer.data = $xPassword

	;Create buffer for salt and move it into the buffer
	If IsString($vSalt) Then
		$xSalt = StringToBinary($vSalt, $SB_UTF8)
	Else
		$xSalt = Binary($vSalt)
	EndIf
	$tSaltBuffer = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xSalt)))
	$tSaltBuffer.data = $xSalt

	;Create buffer for key
	$tKeyBuffer = DllStructCreate(StringFormat("byte data[%i]", $iKeyBitLength / 8))

	;Open algorithm provider
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDeriveKeyPBKDF2", _
                       "handle",   $hAlgorithmProvider, _
                       "struct*",  $tPasswordBuffer, _
                       "ulong",    DllStructGetSize($tPasswordBuffer), _
                       "struct*",  $tSaltBuffer, _
                       "ulong",    DllStructGetSize($tSaltBuffer), _
                       "uint64",   $iIterations, _
                       "struct*",  $tKeyBuffer, _
                       "ulong",    DllStructGetSize($tKeyBuffer), _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		If $hAlgorithmProvider <> -1 Then __CryptoNG_BcryptCloseAlgorithmProvider($hAlgorithmProvider)
		Return SetError(1, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptDeriveKeyPBKDF2 $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, "")
	EndIf

	$xKey = $tKeyBuffer.data
	If $__gbDebugging Then _DebugOut("$xKey = " & $xKey)


	;All is good, return hash
	Return $xKey

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BcryptDestroyHash
; Description ...: Destroy hash object.
; Syntax ........: __CryptoNG_BcryptDestroyHash($hHandle)
; Parameters ....: $hHandle             Handle to hash object.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
; Author ........: TheXman
; Modified ......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroyhash
; ===============================================================================================================================
Func __CryptoNG_BcryptDestroyHash($hHandle)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BcryptDestroyHash()")

	Local $iError = 0


	;Close handle
	DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDestroyHash", "handle",  $hHandle)
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf

	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BcryptDestroyKey
; Description ...: Destroys an encryption key.
; Syntax ........: __CryptoNG_BcryptDestroyKey($hKey)
; Parameters ....: $hHandle             Handle to encryption key.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
; Author ........: TheXman
; Modified ......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey
; ===============================================================================================================================
Func __CryptoNG_BcryptDestroyKey($hKey)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BcryptDestroyKey()")

	Local $iError = 0

	;Close handle
	DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptDestroyKey", "handle",  $hKey)
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf

	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptEncrypt
; Description ...: Encrypt data
; Syntax ........: __CryptoNG_BCryptEncrypt($sAlgorithmId, $vData, $hEncryptionKey)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $vData               Data to be encrypted.
;                  $hEncryptionKey      A handle to the encryption key.
; Return values .: Success:             An encrypted binary string.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - Unable to get hash length property
;                                       2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: If a block cipher algorithm is requested, the generated IV will be the length of the algoritm's
;                  block size and will contain consecutive binary byte values starting from 0x00.  i.e. 0x000102...0F
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
; ===============================================================================================================================
Func __CryptoNG_BCryptEncrypt($sAlgorithmId, $vData, $hEncryptionKey)

	Local $tInputBuffer  = "", _
	      $tOutputBuffer = "", _
		  $tIVBuffer     = "", _
		  $tByteBuffer   = "", _
		  $tUlong        = ""

	Local $iBlockLength  = 0, _
	      $iStatusCode   = 0, _
		  $iError        = 0, _
		  $iOutputLength = 0

	Local $aResult[0]

	Local $xEncryptedData = Binary(""), _
	      $xIV            = Binary(""), _
	      $xData          = Binary("")


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptEncrypt()")

	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$vData        = " & $vData)

	;Get length of key
	$tByteBuffer = __CryptoNG_BCryptGetProperty($hEncryptionKey, $CNG_BCRYPT_KEY_LENGTH)
	If @error Then Return SetError(1, 0, "")
	$tUlong     = _WinAPI_CopyStruct($tByteBuffer, "ulong value")

	;If this is a block cipher (not a stream cipher)
	If $sAlgorithmId <> $CNG_BCRYPT_RC4_ALGORITHM Then
		;Get length of block
		$tByteBuffer = __CryptoNG_BCryptGetProperty($hEncryptionKey, $CNG_BCRYPT_BLOCK_LENGTH)
		If @error Then Return SetError(1, 0, "")
		$tUlong       = _WinAPI_CopyStruct($tByteBuffer, "ulong value")
		$iBlockLength = $tUlong.value
		If $__gbDebugging Then _DebugOut("$iBlockLength = " & $iBlockLength)

		;Create initialization vector (IV) buffer and set its default value (0x000102...)
		$xIV = Binary("")
		For $i = 0 To $iBlockLength - 1
			$xIV &= Binary(Chr($i))
		Next
		$tIVBuffer      = DllStructCreate(StringFormat("byte data[%i]", $iBlockLength))
		$tIVBuffer.data = $xIV
		If $__gbDebugging Then _DebugOut("IV = " & $tIVBuffer.data)
	EndIf

	;Create input buffer and move input to the buffer
	If IsString($vData) Then
		$xData = StringToBinary($vData, $SB_UTF8)
	Else
		$xData = Binary($vData)
	EndIf

	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = $xData

	;Get size of encrypted output
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (Null) : ($tIVBuffer), _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0)    : (DllStructGetSize($tIVBuffer)), _
                       "ptr",      Null, _
                       "ulong*",   0, _
                       "ulong*",   Null, _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0) : ($CNG_BCRYPT_BLOCK_PADDING) _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iOutputLength = $aResult[9]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Output length = " & $iOutputLength)

	;Create output buffer
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", $iOutputLength))

	;Encrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (Null) : ($tIVBuffer), _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0)    : (DllStructGetSize($tIVBuffer)), _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    ($sAlgorithmId = $CNG_BCRYPT_RC4_ALGORITHM) ? (0) : ($CNG_BCRYPT_BLOCK_PADDING) _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$xEncryptedData = $tOutputBuffer.data

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Encrypted data = " & $xEncryptedData)

	Return $xEncryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptEncrypt_AES_GCM
; Description ...: Encrypt data using CBC chaining mode
; Syntax ........: __CryptoNG_BCryptEncrypt_AES_GCM($sAlgorithmId, $vData, $hEncryptionKey, $vNonce, $iAuthTagBytes)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $vData               Data to be encrypted.
;                  $hEncryptionKey      A handle to the encryption key.
;                  $vNonce              AES GCM Nonce.  The Microsoft Primitive Provider requires the length to be 12 bytes.
;                  $iAuthTagBytes       Length of desired auth tag, in bytes.
; Return values .: Success:             A 1D array containing 2 values:
;                                       [0] Binary string containing the encrypted message
;                                       [1] Binary string containing the authorization tag.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_BCryptEncrypt_AES_GCM($sAlgorithmId, $vData, $hEncryptionKey, $vNonce, $iAuthTagBytes)

	Local $tInputBuffer   = "", _
	      $tOutputBuffer  = "", _
		  $tNonceBuffer   = "", _
		  $tAuthTagBuffer = "", _
		  $tAuthInfo      = ""

	Local $iStatusCode   = 0, _
		  $iError        = 0

	Local $aResult[0]

	Local $xEncryptedData = Binary(""), _
	      $xData          = Binary(""), _
		  $xAuthTag       = Binary("")

	Local $aCipherData[2]


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptEncrypt_AES_GCM()")
	If $__gbDebugging Then _DebugOut("$sAlgorithmId  = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$vData         = " & $vData)
	If $__gbDebugging Then _DebugOut("$vNonce        = " & $vNonce)
	If $__gbDebugging Then _DebugOut("$iAuthTagBytes = " & $iAuthTagBytes)


	;Convert variable input data type to its binary representation
	If IsString($vData) Then
		$xData = StringToBinary($vData, $SB_UTF8)
	Else
		$xData = Binary($vData)
	EndIf

	;Create input buffer and move input to the buffer
	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = $xData


	;Create and populate nonce buffer
	$tNonceBuffer      = DllStructCreate(StringFormat("byte data[%s];", BinaryLen($vNonce)))
	$tNonceBuffer.data = Binary($vNonce)


	;Create other buffers
	$tAuthTagBuffer = DllStructCreate(StringFormat("byte data[%s];", $iAuthTagBytes))
	$tOutputBuffer  = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))


	;Create and populate the Auth Info struct
	$tAuthInfo               = DllStructCreate($__gtagBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)

	$tAuthInfo.dwInfoVersion = $CNG_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
	$tAuthInfo.cbSize        = DllStructGetSize($tAuthInfo)

	$tAuthInfo.pbNonce       = DllStructGetPtr($tNonceBuffer)
	$tAuthInfo.cbNonce       = DllStructGetSize($tNonceBuffer)

	$tAuthInfo.pbTag         = DllStructGetPtr($tAuthTagBuffer)
	$tAuthInfo.cbTag         = DllStructGetSize($tAuthTagBuffer)


	;Encrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "struct*",  $tAuthInfo, _
                       "struct*",  Null, _
                       "ulong",    0, _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)


	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$xEncryptedData = $tOutputBuffer.data
	$xAuthTag       = $tAuthTagBuffer.data


	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Encrypted data = " & $xEncryptedData)
	If $__gbDebugging Then _DebugOut("Nonce          = " & $vNonce)
	If $__gbDebugging Then _DebugOut("Auth Tag       = " & $xAuthTag)


	;Populate return value array
	$aCipherData[0] = $xEncryptedData
	$aCipherData[1] = $xAuthTag


	Return $aCipherData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptEncrypt_With_BlockPadding
; Description ...: Encrypt data using CBC chaining mode
; Syntax ........: __CryptoNG_BCryptEncrypt_With_BlockPadding($sAlgorithmId, $sText, $hEncryptionKey, $vIV = Default)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $vData               Data to be encrypted.
;                  $hEncryptionKey      A handle to the encryption key.
;                  $vIV                 [optional] Initialization Vector.  Default is "".
; Return values .: Success:             An encrypted binary string.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_BCryptEncrypt_With_BlockPadding($sAlgorithmId, $vData, $hEncryptionKey, $vIV = "")

	Local $tInputBuffer  = "", _
	      $tOutputBuffer = "", _
		  $tIVBuffer     = ""

	Local $iStatusCode   = 0, _
		  $iError        = 0, _
		  $iOutputLength = 0

	Local $aResult[0]

	Local $xEncryptedData = Binary(""), _
	      $xData          = Binary("")


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptEncrypt_With_BlockPadding()")

	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$vData        = " & $vData)

	;Create input buffer and move input to the buffer
	If IsString($vData) Then
		$xData = StringToBinary($vData, $SB_UTF8)
	Else
		$xData = Binary($vData)
	EndIf

	$tInputBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = $xData

	;Create initialization vector (IV) buffer and set value
	If BinaryLen($vIV) > 0 Then
		$tIVBuffer = DllStructCreate(StringFormat("byte data[%i]", BinaryLen(Binary($vIV))))
		$tIVBuffer.data = Binary($vIV)
		If $__gbDebugging Then _DebugOut("IV = " & $tIVBuffer.data)
	EndIf

	;Get size of encrypted output
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  (BinaryLen($vIV) > 0 ? $tIVBuffer : Null), _
                       "ulong",    (BinaryLen($vIV) > 0 ? DllStructGetSize($tIVBuffer) : 0), _
                       "ptr",      Null, _
                       "ulong*",   0, _
                       "ulong*",   Null, _
                       "ulong",    $CNG_BCRYPT_BLOCK_PADDING _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iOutputLength = $aResult[9]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Output length = " & $iOutputLength)

	;Create output buffer
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", $iOutputLength))

	;Encrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  (BinaryLen($vIV) > 0 ? $tIVBuffer                   : Null), _
                       "ulong",    (BinaryLen($vIV) > 0 ? DllStructGetSize($tIVBuffer) : 0), _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    $CNG_BCRYPT_BLOCK_PADDING _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$xEncryptedData = $tOutputBuffer.data

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Encrypted data = " & $xEncryptedData)

	Return $xEncryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptEncrypt_RSA
; Description ...: Encrypt data RSA public key.
; Syntax ........: __CryptoNG_BCryptEncrypt_RSA($sAlgorithmId, $sText, $hEncryptionKey, $iPadding)
; Parameters ....: $sAlgorithmId        A string algorithm ID. (See algorithm constants)
;                  $vData               Data to be encrypted.
;                  $hEncryptionKey      A handle to the encryption key.
;                  $iPadding            An integer specifying the padding routine to be used.
; Return values .: Success:             An encrypted binary string.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_BCryptEncrypt_RSA($sAlgorithmId, $vData, $hEncryptionKey, $iPadding)

	Local $tInputBuffer  = "", _
	      $tOutputBuffer = ""

	Local $iStatusCode   = 0, _
		  $iError        = 0, _
		  $iOutputLength = 0

	Local $aResult[0]

	Local $xEncryptedData = Binary(""), _
	      $xData          = Binary("")


	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptEncrypt_RSA()")

	If $__gbDebugging Then _DebugOut("$sAlgorithmId = " & $sAlgorithmId)
	If $__gbDebugging Then _DebugOut("$iPadding     = " & $iPadding)

	;Create input buffer and move input to the buffer
	If IsString($vData) Then
		$xData = StringToBinary($vData, $SB_UTF8)
	Else
		$xData = Binary($vData)
	EndIf

	$tInputBuffer = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tInputBuffer.data = $xData

	;Get size of encrypted output
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  Null, _
                       "ulong",    0, _
                       "ptr",      Null, _
                       "ulong*",   Null, _
                       "ulong*",   Null, _
                       "ulong",    $iPadding _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iOutputLength = $aResult[9]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Output length = " & $iOutputLength)

	;Create output buffer
	$tOutputBuffer = DllStructCreate(StringFormat("byte data[%i]", $iOutputLength))

	;Encrypt the input data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptEncrypt", _
                       "handle",   $hEncryptionKey, _
                       "struct*",  $tInputBuffer, _
                       "ulong",    DllStructGetSize($tInputBuffer), _
                       "ptr",      Null, _
                       "struct*",  Null, _
                       "ulong",    0, _
                       "struct*",  $tOutputBuffer, _
                       "ulong",    DllStructGetSize($tOutputBuffer), _
                       "ulong*",   Null, _
                       "ulong",    $iPadding _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptEncrypt $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode    = $aResult[0]
	$xEncryptedData = $tOutputBuffer.data

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	If $__gbDebugging Then _DebugOut("Encrypted data = " & $xEncryptedData)

	Return $xEncryptedData

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptFinalizeKeyPair
; Description ...: Complete a public/private key pair request.
; Syntax ........: __CryptoNG_BCryptFinalizeKeyPair($hKeyPair)
; Parameters ....: $hKeyPair            A handle to the key pair
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
;                                       2 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinalizekeypair
; ===============================================================================================================================
Func __CryptoNG_BCryptFinalizeKeyPair($hKeyPair)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptFinalizeKeyPair()")

	Local $aResult[0]

	Local $iError      = 0, _
	      $iStatusCode = 0


	;Finalize key pair
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptFinalizeKeyPair", _
                       "handle",   $hKeyPair, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptFinalizeKeyPair $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, False)
	EndIf

	;All is good
	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BcryptExportKey
; Description ...: Exports a specified public/private key type.
; Syntax ........: __CryptoNG_BcryptExportKey($hKeyPair, $sKeyBlobType)
; Parameters ....: $hKeyPair            A handle to the key pair
;                  $sKeyType            Identified the specifies the type of key to export. (See RSA Symmetric Key Constants)
; Return values .: Success:             A binary key blob
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
;                                       2 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: Keys are created in a CryptoAPI-compatible key blob.  The key blobs can be converted to PEM or DER encoded
;                  keys using tools like OpenSSL.
;
;                  Convert the key blobs to PEM or DER format using OpenSSL v1.1+:
;
;                  openssl.exe rsa -pubin -inform "MS PUBLICKEYBLOB" -in publickey.blob -outform PEM -out publickey.pem
;                  openssl.exe rsa -inform "MS PRIVATEKEYBLOB" -in privatekey.blob -outform PEM -out privatekey.pem
;
;                  openssl.exe rsa -pubin -inform "MS PUBLICKEYBLOB" -in publickey.blob -outform DER -out publickey.der
;                  openssl.exe rsa -inform "MS PRIVATEKEYBLOB" -in privatekey.blob -outform DER -out privatekey.DER
;
;
;                  Show key blob info using OpenSSL v1.1+:
;
;                  openssl.exe rsa -inform "MS PUBLICKEYBLOB" -pubin -in publickey.blob -noout -text
;                  openssl.exe rsa -inform "MS PRIVATEKEYBLOB" -in privatekey.blob -noout -text
;
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey
; ===============================================================================================================================
Func __CryptoNG_BcryptExportKey($hKeyPair, $sKeyBlobType)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BcryptExportKey()")

	Local $aResult[0]

	Local $iError          = 0, _
	      $iStatusCode     = 0, _
		  $iBufferLength   = 0

	Local $tBuffer = ""

	Local $xKeyBlob = Binary("")


	;Get size of output buffer
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptExportKey", _
                       "handle",   $hKeyPair, _
                       "handle",   Null, _
                       "wstr",     $sKeyBlobType, _
                       "ptr",      Null, _
                       "ulong",    0, _
                       "ulong*",   Null, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, "")
	EndIf

	If $__gbDebugging Then _DebugReportVar("BCryptExportKey $aResult", $aResult)

	;Check status code from dllcall
	$iStatusCode = $aResult[0]
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, "")
	EndIf

	;Get returned value(s) from dllcall
	$iBufferLength = $aResult[6]

	;Create buffer for key
	$tBuffer = DllStructCreate(StringFormat("byte data[%i]", $iBufferLength))

	;Get key
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptExportKey", _
                       "handle",   $hKeyPair, _
                       "handle",   Null, _
                       "wstr",     $sKeyBlobType, _
                       "struct*",  $tBuffer, _
                       "ulong",    DllStructGetSize($tBuffer), _
                       "ulong*",   Null, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, "")
	EndIf

	If $__gbDebugging Then _DebugReportVar("BCryptExportKey $aResult", $aResult)

	;Check status code from dllcall
	$iStatusCode = $aResult[0]
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, "")
	EndIf

	;Copy key blob to variable
	$xKeyBlob = $tBuffer.data

	If $__gbDebugging Then _DebugOut("Exported Key: " & $xKeyBlob)

	;All is good, return value
	Return $xKeyBlob

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptFinishHash
; Description ...: Finish the hash operation.
; Syntax ........: __CryptoNG_BCryptFinishHash($hHashObject)
; Parameters ....: $hHashObject         A handle to the hash object
; Return values .: Success:             A binary hash
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - Unable to get hash length property
;                                       2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
; ===============================================================================================================================
Func __CryptoNG_BCryptFinishHash($hHashObject)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptFinishHash()")

	Local $tDataBuffer = "", _
	      $tByteBuffer = "", _
	      $tUlong      = ""

	Local $aResult[0]

	Local $iError      = 0, _
	      $iStatusCode = 0, _
		  $iHashLength = 0

	Local $xHash = ""


	;Get hash length
	$tByteBuffer = __CryptoNG_BCryptGetProperty($hHashObject, $CNG_BCRYPT_HASH_LENGTH)
	If @error Then Return SetError(1, 0, "")
	$tUlong      = _WinAPI_CopyStruct($tByteBuffer, "ulong value")
	$iHashLength = $tUlong.value

	;Create a buffer and move hash data to it
	$tDataBuffer = DllStructCreate(StringFormat("byte data[%i]", $iHashLength))
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptFinishHash", _
                       "handle",   $hHashObject, _
                       "struct*",  $tDataBuffer, _
                       "ulong",    DllStructGetSize($tDataBuffer), _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, "")
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptFinishHash", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, "")
	EndIf

	;All is good
	$xHash = $tDataBuffer.data
	If $__gbDebugging Then _DebugOut("Hash value = " & $xHash)

	Return $xHash

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptFreeBuffer
; Description ...: Free buffer used by pointer.
; Syntax ........: __CryptoNG_BCryptFreeBuffer($iPointer)
; Parameters ....: $iPointer - Pointer to buffer that needs to be passed.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall to BCryptFreeBuffer function failed
; Author ........: TheXman
; Modified ......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfreebuffer
; ===============================================================================================================================
Func __CryptoNG_BCryptFreeBuffer($iPointer)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptFreeBuffer()")

	Local $iError = 0


	;Free buffer space
	DllCall(__CryptoNG_GetBcryptDllHandle(), "none", "BCryptFreeBuffer", "ptr", $iPointer)
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf

	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_NCryptFreeBuffer
; Description ...: Free buffer used by pointer.
; Syntax ........: __CryptoNG_NCryptFreeBuffer($iPointer)
; Parameters ....: $iPointer - Pointer to buffer that needs to be passed.
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall to NCryptFreeBuffer function failed
; Author ........: TheXman
; Modified ......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreebuffer
; ===============================================================================================================================
Func __CryptoNG_NCryptFreeBuffer($iPointer)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_NCryptFreeBuffer()")

	Local $iError = 0


	;Free buffer space
	DllCall(__CryptoNG_GetNcryptDllHandle(), "none", "NCryptFreeBuffer", "ptr", $iPointer)
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf

	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptGenerateKeyPair
; Description ...: Create an empty public/private key pair.
; Syntax ........: __CryptoNG_BCryptGenerateKeyPair($hAlgorithmProvider, $iKeyBitLength)
; Parameters ....: $hAlgorithmProvider  Handle to an open algorithm provider.
;                  $iKeyBitLength       RSA key length (in bits)
; Return values .: Success:             Handle to key pair.
;                  Failure:             -1 and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall to BCryptGenerateKeyPair function failed
;                                       2 - Bad status code returned from BCryptGenerateKeyPair
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratekeypair
; ===============================================================================================================================
Func __CryptoNG_BCryptGenerateKeyPair($hAlgorithmProvider, $iKeyBitLength)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptGenerateKeyPair()")

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $aResult[0]

	Local $hKey = -1


	;Generate symmetric key
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptGenerateKeyPair", _
                       "handle",   $hAlgorithmProvider, _
                       "handle*",  Null, _
                       "ulong",    $iKeyBitLength, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, -1)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptGenerateKeyPair $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]
	$hKey        = $aResult[2]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, -1)
	EndIf

	If $__gbDebugging Then _DebugOut("$hKey = " & $hKey)

	Return $hKey

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptGenerateSymmetricKey
; Description ...: Generate a symmetric key.
; Syntax ........: __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vSecret)
; Parameters ....: $hAlgorithmProvider  Handle to an open algorithm provider.
;                  $vSecret             Encryption secret/password
; Return values .: Success:             Handle to encryption key.
;                  Failure:             -1 and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall to BCryptGenerateSymmetricKey function failed
;                                       2 - Bad status code returned from BCryptGenerateSymmetricKey
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey
; ===============================================================================================================================
Func __CryptoNG_BCryptGenerateSymmetricKey($hAlgorithmProvider, $vSecret)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptGenerateSymmetricKey()")

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $tSecretBuffer = ""

	Local $aResult[0]

	Local $hKey = -1

	Local $xSecret = Binary("")

	;Create buffer for secret and move it to the buffer
	If IsString($vSecret) Then
		$xSecret = StringToBinary($vSecret, $SB_UTF8)
	Else
		$xSecret = Binary($vSecret)
	EndIf

	$tSecretBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xSecret)))
	$tSecretBuffer.data = $xSecret

	;Generate symmetric key
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptGenerateSymmetricKey", _
                       "handle",   $hAlgorithmProvider, _
                       "handle*",  Null, _
                       "ptr",      Null, _
                       "ulong",    0, _
                       "struct*",  $tSecretBuffer, _
                       "ulong",    DllStructGetSize($tSecretBuffer), _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, -1)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptGenerateSymmetricKey $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]
	$hKey        = $aResult[2]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, -1)
	EndIf

	If $__gbDebugging Then _DebugOut("$vSecret = " & $vSecret)
	If $__gbDebugging Then _DebugOut("$hKey    = " & $hKey)

	Return $hKey

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptGenRandom
; Description ...: Generates a random number
; Syntax ........: __CryptoNG_BCryptGenRandom($hAlgorithmProvider, $iNumberOfBytes)
; Parameters ....: $hAlgorithmProvider  Handle to an open algorithm provider.
;                  $iNumberOfBytes      Number of randomly generated bytes
; Return values .: Success:             Randomly generated number.
;                  Failure:             -1 and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall to BCryptGenRandom function failed
;                                       2 - Bad status code returned from BCryptGenRandom
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
; ===============================================================================================================================
Func __CryptoNG_BCryptGenRandom($hAlgorithmProvider, $iNumberOfBytes)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptGenRandom()")

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $tByteBuffer = ""

	Local $xRandomBytes = Binary("")

	Local $aResult[0]


	;Create buffer to hold the random bytes
	$tByteBuffer = DllStructCreate(StringFormat("byte data[%i]", $iNumberOfBytes))

	;Generate random number
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptGenRandom", _
                       "handle",  $hAlgorithmProvider, _
                       "struct*", $tByteBuffer, _
                       "ulong",   DllStructGetSize($tByteBuffer), _
                       "ulong",   0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, -1)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptGenRandom $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode  = $aResult[0]
	$xRandomBytes = $tByteBuffer.data

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, -1)
	EndIf

	If $__gbDebugging Then _DebugOut("Random bytes = " & $xRandomBytes)

	Return $xRandomBytes

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptGetProperty
; Description ...: Retrieves the value of a named property for a CNG object
; Syntax ........: __CryptoNG_BCryptGetProperty($hObject, $sProperty)
; Parameters ....: $hObject             Handle to the object.
;                  $sProperty           The length property to retrieve. See remarks.
; Return values .: Success:             A byte buffer structure containing the requested property value.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall to BCryptGetProperty function failed
;                                       2 - Bad status code returned from BCryptGetProperty
; Author ........: TheXman
; Modified ......:
; Remarks .......: See Key Storage Property Identifier Constants for $sProperty values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
; ===============================================================================================================================
Func __CryptoNG_BCryptGetProperty($hObject, $sProperty)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptGetProperty()")

	Local $iError        = 0, _
	      $iStatusCode   = 0, _
		  $iBufferLength = 0

	Local $tBuffer = ""

	Local $aResult[0]


	;Get buffer length
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptGetProperty", _
                       "handle",   $hObject, _
                       "wstr",     $sProperty, _
                       "ptr",      Null, _
                       "ulong",    0, _
                       "ulong*",   0, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, Binary(""))
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptGetProperty $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode   = $aResult[0]
	$iBufferLength = $aResult[5]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, Binary(""))
	EndIf

	If $__gbDebugging Then _DebugOut("$iBufferLength = " & $iBufferLength)

	;Get property
	$tBuffer = DllStructCreate(StringFormat("byte data[%i]", $iBufferLength))
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptGetProperty", _
                       "handle",   $hObject, _
                       "wstr",     $sProperty, _
                       "struct*",  $tBuffer, _
                       "ulong",    DllStructGetSize($tBuffer), _
                       "ulong*",   0, _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, Binary(""))
	EndIf
	If $__gbDebugging Then _DebugReportVar("BcryptGetProperty $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, Binary(""))
	EndIf

	If $__gbDebugging Then _DebugOut("$tBuffer = " & $tBuffer.data)

	Return $tBuffer

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptHashData
; Description ...: Hash the provided data
; Syntax ........: __CryptoNG_BCryptHashData($hHashObject, $vData)
; Parameters ....: $hHashObject         A handle to the hash object
;                  $vData               Data to be hashed
; Return values .: Success:             True
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
;                                       2 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
; ===============================================================================================================================
Func __CryptoNG_BCryptHashData($hHashObject, $vData)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptHashData")

	Local $tDataBuffer = ""

	Local $aResult[0]

	Local $xData = Binary("")

	Local $iError      = 0, _
	      $iStatusCode = 0


	;Create a data buffer and move hash data to it
	If IsString($vData) Then
		$xData = BinaryToString($vData, $SB_UTF8)
	Else
		$xData = Binary($vData)
	EndIf

	$tDataBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xData)))
	$tDataBuffer.data = $xData

	;Hash the data
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptHashData", _
                       "handle",   $hHashObject, _
                       "struct*",  $tDataBuffer, _
                       "ulong",    DllStructGetSize($tDataBuffer), _
                       "ulong",    0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptHashData $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, False)
	EndIf

	;All is good
	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BcryptImportKeyPair
; Description ...: Imports a public/private key pair from a key BLOB.
; Syntax ........: __CryptoNG_BcryptImportKeyPair($hKeyPair, $sKeyBlobType)
; Parameters ....: $hAlgorithmProvider  A handle value to the open algorithm provider object
;                  $sKeyBlobFile        Path to key blob file.
;                  $sKeyType            Identifies the type of key contained in the key blob file. (See RSA Symmetric Key Constants)
; Return values .: Success:             A pointer to a BCRYPT_KEY_HANDLE that contains the handle of the imported key.
;                  Failure:             "" and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              1 - DllCall failed
;                                       2 - Bad status code returned from DllCall
;                                       3 - Key blob file does not exist
;                                       4 - Error opening key blob file
; Author ........: TheXman
; Modified ......:
; Remarks .......:
;
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
; ===============================================================================================================================
Func __CryptoNG_BcryptImportKeyPair($hAlgorithmProvider, $sKeyBlobFile, $sKeyBlobType)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BcryptImportKeyPair()")

	Local $aResult[0]

	Local $iError          = 0, _
	      $iStatusCode     = 0

	Local $tBuffer = ""

	Local $hFile = -1, _
	      $hKey  = -1

	Local $xKeyBlob = Binary("")


	;Make sure file exists
	If Not FileExists($sKeyBlobFile) Then Return SetError(3, 0, "")


	;Read binary blob file
	$hFile = FileOpen($sKeyBlobFile, $FO_BINARY)
	If $hFile = -1 Then Return SetError(4, 0, "")

	$xKeyBlob = FileRead($hFile)
	FileClose($hFile)


	;Create a binary buffer, containing key blob, to pass to function
	$tBuffer      = DllStructCreate(StringFormat("byte data[%i]", BinaryLen($xKeyBlob)))
	$tBuffer.data = $xKeyBlob

	If $__gbDebugging Then _DebugReportVar("Public/Private Key Blob", $tBuffer.data)


	;Import key pair
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptImportKeyPair", _
                       "handle",   $hAlgorithmProvider, _
                       "handle",   Null, _
                       "wstr",     $sKeyBlobType, _
                       "handle*",  Null, _
                       "struct*",  $tBuffer, _
                       "ulong",    DllStructGetSize($tBuffer), _
                       "ulong",    $CNG_BCRYPT_NO_KEY_VALIDATION _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, "")
	EndIf

	If $__gbDebugging Then _DebugReportVar("BCryptImportKeyPair $aResult", $aResult)


	;Get returned values from dllcall
	$iStatusCode = $aResult[0]
	$hKey        = $aResult[4]


	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, "")
	EndIf


	;All is good, return handle pointer
	Return $hKey

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptOpenEncryptionAlgorithmProvider
; Description ...: Open an encryption algorithm provider object
; Syntax ........: __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider = "Microsoft Primitve Provider")
; Parameters ....: $sAlgorithmId        A string containing the requested hashing algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_HASH_OPERATION).
;                                       Common values:
;                                       $CNG_BCRYPT_AES_ALGORITHM
;                                       $CNG_BCRYPT_3DES_ALGORITHM
;                                       $CNG_BCRYPT_RC2_ALGORITHM
;                                       $CNG_BCRYPT_RC4_ALGORITHM
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A handle to the algorithm provider.
;                  Failure:             -1 and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
; ===============================================================================================================================
Func __CryptoNG_BCryptOpenEncryptionAlgorithmProvider($sAlgorithmId, $sProvider = "Microsoft Primitive Provider")

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptOpenEncryptionAlgorithmProvider()")

	Local $aResult[0]

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $hAlgorithmProvider = 0


	;Open algorithm provider
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptOpenAlgorithmProvider", _
                       "handle*", 0, _
                       "wstr",    $sAlgorithmId, _
                       "wstr",    $sProvider, _
                       "ulong",   0 _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, -1)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptOpenAlgorithmProvider $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode        = $aResult[0]
	$hAlgorithmProvider = $aResult[1]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, -1)
	EndIf

	;All is good, return the handle
	Return $hAlgorithmProvider

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptOpenHashAlgorithmProvider
; Description ...: Open a hash algorithm provider
; Syntax ........: __CryptoNG_BCryptOpenHashAlgorithmProvider($sAlgorithmId, $bHMAC = False, $sProvider = "Microsoft Primitve Provider")
; Parameters ....: $sAlgorithmId        A string containing the requested hashing algorithm. See remarks.
;                                       More can be found in the UDF.  You can also see all available algorithms on the PC by
;                                       executing the the following function: _CryptoNG_EnumAlgorithms($CNG_BCRYPT_HASH_OPERATION).
;                                       Common values:
;                                       $CNG_BCRYPT_MD5_ALGORITHM
;                                       $CNG_BCRYPT_SHA1_ALGORITHM
;                                       $CNG_BCRYPT_SHA256_ALGORITHM
;                                       $CNG_BCRYPT_SHA384_ALGORITHM
;                                       $CNG_BCRYPT_SHA512_ALGORITHM
;                  $bHMAC               [optional] To do a HMAC hash, set to True. Default is False.
;                  $sProvider           [optional] A string specifying the desired algorithm provider. Default is Microsoft Primitive Provider.
; Return values .: Success:             A handle to the algorithm provider.
;                  Failure:             -1 and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              2 - DllCall failed
;                                       3 - Bad status code returned from DllCall
; Author ........: TheXman
; Modified ......:
; Remarks .......: See CNG Algorithm Identifier Constants for valid $sAlgorithmId values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
; ===============================================================================================================================
Func __CryptoNG_BCryptOpenHashAlgorithmProvider($sAlgorithmId, $bHMAC = False, $sProvider = "Microsoft Primitive Provider")

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptOpenHashAlgorithmProvider()")

	Local $aResult[0]

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $hAlgorithmProvider = 0


	;Open algorithm provider
	$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptOpenAlgorithmProvider", _
                       "handle*", 0, _
                       "wstr",    $sAlgorithmId, _
                       "wstr",    $sProvider, _
                       "ulong",   ($bHMAC) ? ($CNG_BCRYPT_ALG_HANDLE_HMAC_FLAG) : (0) _
                       )
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(2, $iError, -1)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptOpenAlgorithmProvider $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode        = $aResult[0]
	$hAlgorithmProvider = $aResult[1]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(3, $iStatusCode, -1)
	EndIf

	;All is good, return the handle
	Return $hAlgorithmProvider

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_BCryptSetProperty
; Description ...: Sets the value of a named property for a CNG object.
; Syntax ........: __CryptoNG_BCryptSetProperty($hObject, $sProperty, $vValue)
; Parameters ....: $hObject             Handle to the object.
;                  $sProperty           The property to be set.  See remarks.
;                  $vValue              The value of the property to be set.
; Return values .: Success:             True.
;                  Failure:             False and sets @error flag to non-zero.
;                                       @extended is set to @error or status code from function that failed.
;                  @error:              -1 - Unrecognized variable type
;                                        1 - DllCall function failed
;                                        2 - Bad status code returned from function
; Author ........: TheXman
; Modified ......:
; Remarks .......: See Cryptography Primitive Property Identifier Constants for property name values.
; Related .......: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty
; ===============================================================================================================================
Func __CryptoNG_BCryptSetProperty($hObject, $sProperty, $vValue)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_BCryptSetProperty()")

	Local $iError      = 0, _
	      $iStatusCode = 0

	Local $aResult[0]


	;Call set property based on value type
	Switch VarGetType($vValue)
		Case "String"
			$aResult = DllCall(__CryptoNG_GetBcryptDllHandle(), "int", "BCryptSetProperty", _
							   "handle",   $hObject, _
							   "wstr",     $sProperty, _
							   "wstr",     $vValue, _
							   "ulong",    BinaryLen($vValue), _
							   "ulong",    0 _
							   )
		Case Else
			$__gsLastErrorMessage = "An unrecognized variable type was encountered in __CryptoNG_BCryptSetProperty() (" & VarGetType($vValue) & ")"
			Return SetError(-1, $iError, False)
	EndSwitch
	If @error Then
		$iError = @error
		$__gsLastErrorMessage = __CryptoNG_DllCallErrorMessage($iError)
		Return SetError(1, $iError, False)
	EndIf
	If $__gbDebugging Then _DebugReportVar("BCryptSetProperty $aResult", $aResult)

	;Get returned values from dllcall
	$iStatusCode = $aResult[0]

	;Check status code from dllcall
	If $iStatusCode <> $CNG_STATUS_SUCCESS Then
		$__gsLastErrorMessage = __CryptoNG_StatusMessage($iStatusCode)
		Return SetError(2, $iStatusCode, False)
	EndIf

	Return True

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_CloseBcryptDllHandle
; Description ...: Close Dll handle.
; Syntax ........: __CryptoNG_CloseBcryptDllHandle()
; Parameters ....: None
; Return values .: None
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; ===============================================================================================================================
Func __CryptoNG_CloseBcryptDllHandle()

	;Close bcrypt.dll handle
	DllClose($__ghBcryptDll)

	If $__gbDebugging Then _DebugOut(@CRLF & "Bcrypt.dll successfully closed")

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_CloseNcryptDllHandle
; Description ...: Close Dll handle.
; Syntax ........: __CryptoNG_CloseNcryptDllHandle()
; Parameters ....: None
; Return values .: None
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; ===============================================================================================================================
Func __CryptoNG_CloseNcryptDllHandle()

	;Close bcrypt.dll handle
	DllClose($__ghNcryptDll)

	If $__gbDebugging Then _DebugOut(@CRLF & "Ncrypt.dll successfully closed")

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_DllCallErrorMessage
; Description ...: Returns the error message based on @error from DllCall
; Syntax ........: __CryptoNG_DllCallErrorMessage($iError)
; Parameters ....: $iError              @error from DllCall
; Return values .: Error message.
; Author ........: TheXman
; ===============================================================================================================================
Func __CryptoNG_DllCallErrorMessage($iError)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_DllCallErrorMessage()")

	Local $sErrorMessage = ""

	Switch $iError
		Case 1
			$sErrorMessage = "Unable to use the DLL file."
		Case 2
			$sErrorMessage = "Unknown return type."
		Case 3
			$sErrorMessage = "Function not found in the DLL file."
		Case 4
			$sErrorMessage = "Bad number of parameters."
		Case 5
			$sErrorMessage = "Bad parameter."
		Case Else
			$sErrorMessage = "Unrecognized error.  @error = " & $iError
	EndSwitch

	Return $sErrorMessage

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_GetBcryptDllHandle
; Description ...: Return single instance of Dll handle.
; Syntax ........: __CryptoNG_GetBcryptDllHandle()
; Parameters ....: None
; Return values .: Success:             Handle to Dll
;                  Failure:             Exit with error message
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; ===============================================================================================================================
Func __CryptoNG_GetBcryptDllHandle()

	;If dll not opened yet
	If $__ghBcryptDll = -1 Then

		If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_GetBcryptDllHandle()")

		;Open dll handle
		$__ghBcryptDll = DllOpen("bcrypt.dll")
		If $__ghBcryptDll = -1 Then Exit MsgBox($MB_ICONERROR + $MB_TOPMOST, "CRYPTONG ERROR", "Unable to open Bcrypt.dll")

		If $__gbDebugging Then _DebugOut("- Bcrypt.dll successfully opened")

		;Register function to close dll handle on exit
		OnAutoItExitRegister("__CryptoNG_CloseBcryptDllHandle")
	EndIf

	Return $__ghBcryptDll

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_GetNcryptDllHandle
; Description ...: Return single instance of Dll handle.
; Syntax ........: __CryptoNG_GetNcryptDllHandle()
; Parameters ....: None
; Return values .: Success:             Handle to Dll
;                  Failure:             Exit with error message
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; ===============================================================================================================================
Func __CryptoNG_GetNcryptDllHandle()

	;If dll not opened yet
	If $__ghNcryptDll = -1 Then

		If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_GetNcryptDllHandle()")

		;Open dll handle
		$__ghNcryptDll = DllOpen("ncrypt.dll")
		If $__ghNcryptDll = -1 Then Exit MsgBox($MB_ICONERROR + $MB_TOPMOST, "CRYPTONG ERROR", "Unable to open Ncrypt.dll")

		If $__gbDebugging Then _DebugOut("- Ncrypt.dll successfully opened")

		;Register function to close dll handle on exit
		OnAutoItExitRegister("__CryptoNG_CloseNcryptDllHandle")
	EndIf

	Return $__ghNcryptDll

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_IsKeyBitLengthValid
; Description ...: Determine whether key bit length is valid for a specified algorithm
; Syntax ........: __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey)
; Parameters ....: $hAlgorithmProvider  A handle value to the open algorithm provider object.
;                  $vEncryptionKey      An encryption key.
; Return values .: Success:             True if bit length is valid and false if bit length is not valid.
;                  Failure:             False and sets @error flag to non-zero.
;                                       @error values:
;                                       1 - DllCall function failed
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_IsKeyBitLengthValid($hAlgorithmProvider, $vEncryptionKey)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_IsKeyBitLengthValid()")


	Local $iEncryptKeyBitLength = BinaryLen($vEncryptionKey) * 8

	Local $tByteBuffer       = "", _
	      $tKeyLengthsStruct = ""


	If $__gbDebugging Then _DebugOut("$iEncryptKeyBitLength = " & $iEncryptKeyBitLength)

	;Get valid encryption key lengths for algorithm
	$tByteBuffer = __CryptoNG_BCryptGetProperty($hAlgorithmProvider, $CNG_BCRYPT_KEY_LENGTHS)
	If @error Then Return SetError(1, 0, "")

	;Use KEY_LENGTHS_STRUCT to access byte buffer
	$tKeyLengthsStruct = DllStructCreate($__gtagBCRYPT_KEY_LENGTHS_STRUCT, DllStructGetPtr($tByteBuffer))

	If $__gbDebugging Then _DebugOut("dwMinLength = " & $tKeyLengthsStruct.dwMinLength)
	If $__gbDebugging Then _DebugOut("dwMaxLength = " & $tKeyLengthsStruct.dwMaxLength)
	If $__gbDebugging Then _DebugOut("dwIncrement = " & $tKeyLengthsStruct.dwIncrement)

	;Return boolean based on bit length
	If $iEncryptKeyBitLength < $tKeyLengthsStruct.dwMinLength Then
		Return False
	ElseIf $iEncryptKeyBitLength > $tKeyLengthsStruct.dwMaxLength Then
		Return False
	ElseIf Mod($iEncryptKeyBitLength, $tKeyLengthsStruct.dwIncrement) <> 0 Then
		Return False
	Else
		Return True
	EndIf

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_IsAuthTagByteLengthValid
; Description ...: Determine whether AES GCM auth tag length is valid.
; Syntax ........: __CryptoNG_IsAuthTagBitLengthValid($hAlgorithmProvider, $iAuthTagBytes)
; Parameters ....: $hAlgorithmProvider  A handle value to the open algorithm provider object.
;                  $iAuthTagBytes       Length of desired authorization tag in bytes.
; Return values .: Success:             True if length is valid and false if length is not valid.
;                  Failure:             False and sets @error flag to non-zero.
;                                       @error values:
;                                       1 - DllCall function failed
; Author ........: TheXman
; Modified ......:
; Remarks .......:
; Related .......:
; ===============================================================================================================================
Func __CryptoNG_IsAuthTagByteLengthValid($hAlgorithmProvider, $iAuthTagBytes)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_IsAuthTagBitLengthValid()")


	Local $tByteBuffer       = "", _
	      $tKeyLengthsStruct = ""


	If $__gbDebugging Then _DebugOut("$iAuthTagBytes = " & $iAuthTagBytes)

	;Get valid auth tag lengths for algorithm
	$tByteBuffer = __CryptoNG_BCryptGetProperty($hAlgorithmProvider, $CNG_BCRYPT_AUTH_TAG_LENGTH)
	If @error Then Return SetError(1, 0, False)

	;Use KEY_LENGTHS_STRUCT to access byte buffer
	$tKeyLengthsStruct = DllStructCreate($__gtagBCRYPT_KEY_LENGTHS_STRUCT, DllStructGetPtr($tByteBuffer))

	If $__gbDebugging Then _DebugOut("dwMinLength = " & $tKeyLengthsStruct.dwMinLength)
	If $__gbDebugging Then _DebugOut("dwMaxLength = " & $tKeyLengthsStruct.dwMaxLength)
	If $__gbDebugging Then _DebugOut("dwIncrement = " & $tKeyLengthsStruct.dwIncrement)

	;Return boolean based on bit length
	If $iAuthTagBytes < $tKeyLengthsStruct.dwMinLength Then
		Return False
	ElseIf $iAuthTagBytes > $tKeyLengthsStruct.dwMaxLength Then
		Return False
	ElseIf Mod($iAuthTagBytes, $tKeyLengthsStruct.dwIncrement) <> 0 Then
		Return False
	Else
		Return True
	EndIf

EndFunc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __CryptoNG_StatusMessage
; Description ...: Returns the error message based on status code
; Syntax ........: __CryptoNG_StatusMessage($iStatusCode)
; Parameters ....: $iStatusCode              @error from DllCall
; Return values .: Status message.
; Author ........: TheXman
; ===============================================================================================================================
Func __CryptoNG_StatusMessage($iStatusCode)

	If $__gbDebugging Then _DebugOut(@CRLF & "Function: __CryptoNG_StatusMessage()")

	Local $sStatusMessage = ""


	Switch $iStatusCode
		Case $CNG_STATUS_SUCCESS
			$sStatusMessage = "The operation completed successfully. "
		Case $CNG_STATUS_INVALID_PARAMETER, $NTE_INVALID_PARAMETER
			$sStatusMessage = "An invalid parameter was passed to a service or function."
		Case $CNG_STATUS_NO_MEMORY, $NTE_NO_MEMORY
			$sStatusMessage = "Not enough virtual memory or paging file quota is available to complete the specified operation."
		Case $CNG_STATUS_NOT_FOUND
			$sStatusMessage = "The object was not found."
		Case $CNG_STATUS_BUFFER_TOO_SMALL
			$sStatusMessage = "The buffer is too small to contain the entry."
		Case $CNG_STATUS_INVALID_HANDLE
			$sStatusMessage = "An invalid HANDLE was specified."
		Case $CNG_STATUS_DATA_ERROR
			$sStatusMessage = "An error occurred in reading or writing data."
		Case $CNG_STATUS_NOT_SUPPORTED
			$sStatusMessage = "The request is not supported."
		Case $CNG_STATUS_AUTH_TAG_MISMATCH
			$sStatusMessage = "The computed authentication tag did not match the input authentication tag."
		Case $NTE_BAD_FLAGS
			$sStatusMessage = "An invalid flag was passed to the function."
		Case $NTE_BAD_DATA
			$sStatusMessage = "Bad data supplied to function."
		Case Else
			$sStatusMessage = StringFormat("Unrecognized status code.  (%X)", $iStatusCode)
	EndSwitch

	Return $sStatusMessage

EndFunc
