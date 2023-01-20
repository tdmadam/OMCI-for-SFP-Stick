
Verification of GPON OMCI communications relies on the implementation of the CRC32 algorithm found in the [ITU-T I363.5 ATM Adaptation Layer : Type 5 AAL](https://www.itu.int/rec/T-REC-I.363.5/en) specification.
The same algorithm is used for bzip2 file compression.


</br>

### Example of calculating CRC32 using online calculator
https://crccalc.com/

```
00 00 10 0A 00 0B 04 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 28
```






![crc32aal5](https://user-images.githubusercontent.com/52431348/213610171-6d1d6d6b-b301-4eb1-b826-e28c08ee51c6.png)



</br>

### Example of calculating CRC32 using python libscrc
https://github.com/hex-in/libscrc


```
>>>  import libscrc
>>>  hex(libscrc.aal5(b'\x00\x00\x10\x0A\x00\x0B\x04\x01\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x28'))
'0x651ad04f
```
