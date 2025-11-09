# KISIA 교육

## AI를 활용한 disassemble code 해석 하기
```ASM
CODE:00401000                 public start
CODE:00401000 start           proc near
CODE:00401000                 push    0               ; uType
CODE:00401002                 push    offset Caption  ; "abex' 1st crackme"
CODE:00401007                 push    offset Text     ; "Make me think your HD is a CD-Rom."
CODE:0040100C                 push    0               ; hWnd
CODE:0040100E                 call    MessageBoxA
CODE:00401013                 push    offset RootPathName ; "c:\\"
CODE:00401018                 call    GetDriveTypeA
CODE:0040101D                 inc     esi
CODE:0040101E                 dec     eax
CODE:0040101F                 jz      short $+2
CODE:00401021
CODE:00401021 loc_401021:                             ; CODE XREF: start+1F↑j
CODE:00401021                 inc     esi
CODE:00401022                 inc     esi
CODE:00401023                 dec     eax
CODE:00401024                 cmp     eax, esi
CODE:00401026                 jz      short loc_40103D
CODE:00401028                 push    0               ; uType
CODE:0040102A                 push    offset aError   ; "Error"
CODE:0040102F                 push    offset aNahThisIsNotAC ; "Nah... This is not a CD-ROM Drive!"
CODE:00401034                 push    0               ; hWnd
CODE:00401036                 call    MessageBoxA
CODE:0040103B                 jmp     short loc_401050
CODE:0040103D ; ---------------------------------------------------------------------------
CODE:0040103D
CODE:0040103D loc_40103D:                             ; CODE XREF: start+26↑j
CODE:0040103D                 push    0               ; uType
CODE:0040103F                 push    offset aYeah    ; "YEAH!"
CODE:00401044                 push    offset aOkIReallyThink ; "Ok, I really think that your HD is a CD"...
CODE:00401049                 push    0               ; hWnd
CODE:0040104B                 call    MessageBoxA
```

## AI를 활용한 취약점 분석
```c++
#include <stdio.h> 
#include <string.h>

void secret_function() {
    printf("\n[+] Secret function called! This should not be executed normally.\n");
}

void get_username() {
    char buffer[16]; 
    printf("Enter your name: ");
    gets(buffer); 
    printf("Hello, %s!\n", buffer);
}

int main() {
    get_username(); 

    printf("\n[+] Program finished normally.\n");
    return 0;
}
```
