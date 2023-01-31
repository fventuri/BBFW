# Radare2 utilities

## Create a file with all the function signatures to send to symgrate.com
```
r2 -i prelude.r2 -i 20221112.r2 -i functions.r2 -qq --
```

## Send the file /tmp/symgrate.txt to symgrate.com to resolve the functions:
```
curl -s -S -d @/tmp/symgrate.txt -X POST https://symgrate.com/jfns | jq > /tmp/symgrate.out
```
