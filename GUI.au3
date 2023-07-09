#NoTrayIcon
#include <ButtonConstants.au3>
#include <ComboConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include <Constants.au3>
#include <CryptoNG.au3>

Local $hInput[4], $hOutput

Example()

Func Example()
    Local $hGUI, $btnDerive, $btnCopy, $msg

    ; Create GUI
    $hGUI = GUICreate("PBKDF2 Key Derivation", 400, 320)

    ; Create labels
    GUICtrlCreateLabel("Password:", 10, 10, 60, 20)
    GUICtrlCreateLabel("Salt:", 10, 40, 60, 20)
    GUICtrlCreateLabel("Iterations:", 10, 70, 60, 20)
    GUICtrlCreateLabel("Key Length:", 10, 100, 60, 20)

    ; Create input fields
    $hInput[0] = GUICtrlCreateInput("", 80, 10, 310, 20)
    $hInput[1] = GUICtrlCreateInput("", 80, 40, 310, 20)
    $hInput[2] = GUICtrlCreateInput("", 80, 70, 310, 20)
    $hInput[3] = GUICtrlCreateInput("", 80, 100, 310, 20)

    ; Create Derive button
    $btnDerive = GUICtrlCreateButton("Derive Key", 10, 130, 80, 30)

    ; Create output area
    $hOutput = GUICtrlCreateEdit("", 10, 170, 380, 100, BitOR($ES_READONLY, $ES_AUTOVSCROLL, $ES_WANTRETURN))
    GUICtrlSetFont($hOutput, 9, 400, 0, "Courier New") ; Definir a fonte monoespaçada

    ; Create Copy button
    $btnCopy = GUICtrlCreateButton("Copy", 10, 280, 80, 30)

    ; Show GUI
    GUISetState(@SW_SHOW)

    ; Event loop
    While 1
        $msg = GUIGetMsg()
        Switch $msg
            Case $GUI_EVENT_CLOSE
                ExitLoop
            Case $btnDerive
                OnDeriveClick()
            Case $btnCopy
                OnCopyClick()
        EndSwitch
    WEnd

    ; Close the GUI
    GUIDelete($hGUI)
EndFunc

Func OnDeriveClick()
    Local $password, $salt, $iterations, $keyLength, $derivedKey

    ; Get input values
    $password = GUICtrlRead($hInput[0])
    $salt = GUICtrlRead($hInput[1])
    $iterations = GUICtrlRead($hInput[2])
    $keyLength = GUICtrlRead($hInput[3])

    ; Call PBKDF2 example function
    $derivedKey = pbkdf2_example($password, $salt, $iterations, $keyLength)

    ; Remove "0x" from the beginning of the derived key
    If StringLeft($derivedKey, 2) = "0x" Then
        $derivedKey = StringTrimLeft($derivedKey, 2)
    EndIf

    ; Convert derived key to lowercase
    $derivedKey = StringLower($derivedKey)

    ; Set output
    GUICtrlSetData($hOutput, $derivedKey)
EndFunc

Func pbkdf2_example($password, $salt, $iterations, $keyLength)
    Local $xPasswordHash = ""

    ; PBKDF2 Example
    $xPasswordHash = _CryptoNG_PBKDF2($password, $salt, $iterations, $keyLength, $CNG_BCRYPT_SHA256_ALGORITHM)
    If @error Then
        ConsoleWrite("ERROR: " & _CryptoNG_LastErrorMessage() & @CRLF)
        Return ""
    EndIf

    Return $xPasswordHash
EndFunc

Func OnCopyClick()
    ; Copy output to clipboard
    ClipPut(GUICtrlRead($hOutput))
EndFunc
