# Present Cipher

We have implemented the PRESENT Cipher, Both 80 bit and 128 bit in Python.

  - Generate Difference Distribution Table
  - Generate Linear Approximation Table
  - Differential attack on three round of Present Cipher

## Encrytion

Run present.py file in root folder.

```sh
$ python3 present.py
```
#### Demo
```sh
$ python3 ./present.py
Enter 8 Characters
Hellowrd
Enter key in hex, 20 hex characters for 80bit  or 32 hex characters for 128bit
123456789a123456789a
Encryption:  97ee45bb06d0a6e6
```

## DDT and LAT
### For DDT
```sh
$ python3 ./differentialAnalysis/DDT.py
```
### For LAT
```sh
$ python3 ./linearAnalysis/LAT.py
```
## Running Differential Attack on 3 Round Present Cipher
```sh
$ python3 ./differentialAnalysis/differentialAttack.py
```
### Demo
```sh
$ python3 ./differentialAnalysis/differentialAttack.py
Master Key -> ded47b8fd70a0dab8f99
Filtered:  16384  Pairs
Possible Keys
0x0000000000010101 0.0078125
0x0001000100000100 0.00390625
0x0000000001010000 0.00390625
0x0000000001010001 0.015625
0x0000000101010001 0.00390625
0x0001000001000000 0.00390625
0x0001000101000000 0.0078125
0x0001000101000001 0.00390625
0x0000000001000101 0.0078125
0x0000000001010100 0.015625
0x0000000001010101 0.0625
0x0000000101000101 0.0078125
0x0000000101010101 0.015625
0x0001000001000100 0.015625
0x0001000001010101 0.0078125
0x0001000101000100 0.03125
0x0001000101000101 0.015625
0x0001000101010101 0.0078125
Actual Subkey for last round:  0xb836ba3e677b51ef
```
Please note that possible key reffers to 8 bits guessed in Differential attack, non guessed bits are 0.

## Corelation Analaysis
Install Jupiter notebook
Import corelationAnalysis/corelation.ipynb in Jupiter notebook and run.

## Video Presentation Link
 [Google drive link for presentation](https://drive.google.com/file/d/1ENFQ65MiHmECWrCaT5YCCp1ueh6gPs0F/view?usp=sharing) 
