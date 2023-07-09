package require Tk
source pbkdf2.tcl

# Function to copy the text to the clipboard
proc copyText {text} {
    clipboard clear
    clipboard append $text
}

# Function to derive the key using PBKDF2
proc deriveKey {} {
    set password [.passwordInput get]
    set salt [.saltInput get]
    set iterations [.iterationsInput get]
    set key_length [.keyLengthInput get]

    set derived_key [::pbkdf2::pbkdf2 $password $salt $iterations $key_length]

    .outputArea delete 1.0 end
    .outputArea insert end [binary encode hex $derived_key]
}

# Function to copy the derived key to the clipboard
proc copyDerivedKey {} {
    set derived_key [.outputArea get 1.0 end]
    copyText $derived_key
}

# Create the main window
wm title . "PBKDF2 Key Derivation"
wm geometry . 400x300

# Create the labels
label .passwordLabel -text "Password:"
label .saltLabel -text "Salt:"
label .iterationsLabel -text "Iterations:"
label .keyLengthLabel -text "Key Length:"

# Position the labels
grid .passwordLabel -row 0 -column 0 -sticky "e"
grid .saltLabel -row 1 -column 0 -sticky "e"
grid .iterationsLabel -row 2 -column 0 -sticky "e"
grid .keyLengthLabel -row 3 -column 0 -sticky "e"

# Create the text input fields
entry .passwordInput -show "*"
entry .saltInput
entry .iterationsInput -validate key -validatecommand {string is integer %P}
entry .keyLengthInput -validate key -validatecommand {string is integer %P}

# Position the text input fields
grid .passwordInput -row 0 -column 1 -sticky "ew"
grid .saltInput -row 1 -column 1 -sticky "ew"
grid .iterationsInput -row 2 -column 1 -sticky "ew"
grid .keyLengthInput -row 3 -column 1 -sticky "ew"

# Create the button
button .deriveButton -text "Derive Key" -command {deriveKey}

# Position the button
grid .deriveButton -row 4 -columnspan 2 -sticky "ew"

# Create the output area
text .outputArea

# Position the output area
grid .outputArea -row 5 -columnspan 2 -sticky "nsew"

# Create the copy button
button .copyButton -text "Copy" -command {copyDerivedKey}

# Position the copy button
grid .copyButton -row 6 -columnspan 2 -sticky "ew"

# Configure margins
grid configure .passwordInput -padx 10 -pady 5
grid configure .saltInput -padx 10 -pady 5
grid configure .iterationsInput -padx 10 -pady 5
grid configure .keyLengthInput -padx 10 -pady 5
grid configure .outputArea -padx 10 -pady 5
grid configure .deriveButton -padx 10 -pady 5
grid configure .copyButton -padx 10 -pady 5

# Configure resizing of grid cells
grid columnconfigure . 1 -weight 1
grid rowconfigure . 5 -weight 1

# Start the main Tcl/Tk event loop
wm deiconify .
tkwait window .
