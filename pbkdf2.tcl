 package require sha256

 namespace eval ::pbkdf2 {
         variable version 1.0.5
 }

 proc ::pbkdf2::pbkdf2 {password salt count dklen} {
         set hlen 32 ;# 256 bits -> 32 bytes
         if {$dklen > (2**32-1)*$hlen} { error "derived key too long" }
         set l [expr {int(ceil(double($dklen)/$hlen))}]
         set dkl [list]
         for {set i 1} {$i <= $l} {incr i} {
                 set xsor [debin [set salty [::sha2::hmac -bin -key $password "$salt[binary format I $i]"]]]
                 for {set j 1} {$j < $count} {incr j} { set xsor [expr {$xsor ^ [debin [set salty [::sha2::hmac -bin -key $password $salty]]]}] }
                 lappend dkl $xsor
         }
         set dk [list]
         foreach dkp $dkl {
                 set dkhl [list]
                 while {$dkp > 0} {
                         lappend dkhl [binary format Iu* [expr {$dkp & 0xFFFFFFFF}]]
                         set dkp [expr {$dkp >> 32}]
                 }
                 lappend dk [join [lreverse $dkhl] ""]
         }
         return [string range [join $dk ""] 0 [incr dklen -1]]
 }

 proc ::pbkdf2::debin {vat} {
         binary scan $vat Iu* rl
         return [expr {([lindex $rl 0] << 224) + ([lindex $rl 1] << 192) + ([lindex $rl 2] << 160) + ([lindex $rl 3] << 128) + ([lindex $rl 4] << 96) + ([lindex $rl 5] << 64) + ([lindex $rl 6] << 32) + [lindex $rl 7]}]
 }

 package provide pbkdf2 $::pbkdf2::version


set pass [::pbkdf2::pbkdf2 pass 00 1024 16]
puts [binary encode hex $pass]
