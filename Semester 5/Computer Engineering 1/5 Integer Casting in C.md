---
Theorie:
  - "[[5 Integer Casting in C.pdf]]"
Quiz: "[[5 Integer Casting in C Q.pdf]]"
---
# Integer Ranges
![[Pasted image 20241115194431.png|800]]
# Type Conversion
![[IMG_23C6ACF5B1DA-1.jpeg|800]]

# Extension
![[Pasted image 20241115193929.png|800]]
# Truncation
![[Pasted image 20241115194228.png|800]]
# Casting
![[IMG_1EEBD0669B91-1.jpeg|800]]

**Example**

![[IMG_970B65DC1B69-1.jpeg|800]]
# Sign Extension
## Sign Extension (Signed Values)
Extends a smaller signed value (e.g., 8-bit or 16-bit) to a larger word size (32-bit), while preserving the sign of the original value.
- If the most significant bit (MSB) of the smaller value is 1, the extended bits are filled with 1 (negative sign).
- If the MSB is 0, the extended bits are filled with 0.

| Instruction | Function                                       |
| ----------- | ---------------------------------------------- |
| SXTB        | Sign-extends an 8-bit value to a 32-bit value. |
| SXTH        | Sign-extends a 16-bit value to a 32-bit value. |

```
SXTB R3, R10   ; Extract the lowest byte from R10, sign-extend it, and store it in R3.
```

## Zero Extension (Unsigned Values)
Extends a smaller unsigned value (e.g., 8-bit or 16-bit) to a larger word size (32-bit) by filling the extended bits with 0.
- Ensures that the original value remains non-negative after extension.

| Instruction | Function                                       |
| ----------- | ---------------------------------------------- |
| UXTB        | Zero-extends an 8-bit value to a 32-bit value. |
| UXTH        | Zero-extends a 16-bit value to a 32-bit value. |

```
UXTH R2, R3    ; Extract the lower 16 bits from R3, zero-extend them, and store them in R2.
```