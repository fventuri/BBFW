# analyse functions and sort them
af@@ sym.*
aac
#aap
aflsa
?e Functions found: `afl~?`
#afl > /tmp/functions.txt

# create and dump function signatures
zaF
#z*|awk '$3=="b" {print $2, substr($4, 0, 36)}' > /tmp/funsigs.txt
z*|awk '$3=="b" {b=substr($4,0,36)} $3=="o" && length(b) == 36 {print substr($4,3) "=" b "&"}' > /tmp/symgrate.txt
