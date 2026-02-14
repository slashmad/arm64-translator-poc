# Nästa steg mot Android-bridge

## Status (nuvarande läge)

- Grundläggande integer-ISA, branch/control-flow, minnesformer, exclusive/atomics och spill för `x11..x30` finns i PoC.
- `SP`-alias finns nu för:
  - `ADD/SUB (imm)` i `Rd/Rn` (inkl. `WSP` i 32-bit-formerna)
  - `LDP/STP` (offset + post/pre-index)
  - single-register minnesformer (`LDR/STR`, `LDUR/STUR`, `LDRB/H/SB/SH/SW`, `LDURB/H/SB/SH`, post/pre-index)
- `WZR/XZR` i `Rt` stöds nu för single-register minnesformer:
  - `STR*` använder zero-store när `Rt = WZR/XZR`
  - `LDR*` gör write-discard när `Rt = WZR/XZR`
- `WZR/XZR` i `Rt/Rt2` stöds nu även för `LDP/STP` (`X/W`, offset + post/pre-index):
  - `STP*` använder zero-store när `Rt` eller `Rt2` är `WZR/XZR`
  - `LDP*` gör write-discard när `Rt` eller `Rt2` är `WZR/XZR`
- Registerbranch-former accepterar nu `XZR` (`BR/BLR/RET`), vilket ger branch-target `0`.
- `CBZ/CBNZ` har nu både `W`/`X`-former och `WZR/XZR`-stöd.
- `TBZ/TBNZ` accepterar nu `WZR/XZR` och täcks av både `W`- och `X`-regressionstester.
- `ADR/ADRP` stöder nu write-discard till `XZR` och spill-writeback för omappade destinationsregister.
- `LDXR/LDAXR/LDAR`-laster accepterar nu `Rt = WZR/XZR` med write-discard.
- `STXRB/STXRH/STXR` accepterar nu `Rt = WZR/XZR` med zero-store.
- `STLXRB/STLXRH/STLXR` accepterar nu `Rt = WZR/XZR` med zero-store.
- `STXR/STLXR` accepterar nu även `Ws = WZR` för status-discard.
- `STLRB/STLRH/STLR` accepterar nu `Rt = WZR/XZR` med zero-store.
- `LDXR/LDAXR/LDAR/STXR/STLXR/STLR` accepterar nu även `SP` som basregister.
- `SWP/LDADD/LDCLR/LDEOR/LDSET`, `CAS*` och `CASP*` accepterar nu även `SP` som basregister.
- Spill-regressioner för atomics/exclusives/CAS/CASP täcker nu även `SP`-basformer.
- Spill-regressioner täcker nu även `CASA/CASL/CASAL` och byte/halfword-`CAS*` med `SP`-bas.
- `stress-spill-atomics` stressar nu både `Xn`- och `SP`-bas för `SWP/LDADD`, `CAS/CASA/CASL/CASAL/CASB/CASAH` och hela `CASP`-familjen (`CASP/CASPA/CASPL/CASPAL`, 32/64).
- AdvSIMD bitvis ALU har startats med `AND/BIC/ORR/EOR` för `Vd.{8B,16B}` (`Q=0/1`).
- AdvSIMD immediate-stöd innehåller nu `MOVI Vd.{8B,16B}, #imm8` samt `MOVI Vd.2D` för `#0/#-1`.
- AdvSIMD aritmetik innehåller nu `SQRDMLAH/SQRDMLSH Vd.{2S,4S}, Vn.{2S,4S}, Vm.{2S,4S}`.
- Logical shifted-register täcker nu även `ORN` (`W/X`) och `MVN`-alias (`Rn = WZR/XZR`).
- `EXTR` (`W/X`) stöds nu, inklusive `ROR`-alias när `Rn == Rm`.
- Conditional compare stöder nu `CCMP/CCMN` för både register- och immediate-former (`W/X`) med korrekt fallback till imm-NZCV när villkoret inte håller.
- FP conditional compare stöder nu `FCCMP/FCCMPE` för `S/D`-former, inklusive unordered/NaN-NZCV.
- FP compare stöder nu `FCMP/FCMPE` för `S/D` (register + `#0.0`-former).
- FP scalar ALU stöder nu `FADD/FSUB/FMUL` för `S/D`.
- FP scalar ALU stöder nu även `FDIV` för `S/D`.
- FP/GPR-bridge stöder nu `FMOV W<->S` och `FMOV X<->D`.
- FP/int-konverteringar stöder nu `SCVTF/UCVTF` och `FCVTZS/FCVTZU`, inklusive explicit unsigned-högintervall (`2^31`/`2^63`) i `UCVTF/FCVTZU`.
- SIMD/FP-minnesformer stöder nu även scalar `LDR/STR S` och `LDR/STR D` (unsigned imm + post/pre-index + unscaled), samt `STP/LDP D` (signed offset).
- Integer minnesformer stöder nu även `LDURSW` (unscaled) och `LDRSH` med `W`-destination (post/pre, unscaled, unsigned imm).
- Unsupported-opcodes är nu exekveringsdrivna: de ger runtime-exit först när pathen faktiskt körs och kan loggas via `--log-unsupported`/`TINY_DBT_LOG_UNSUPPORTED`.
- ELF-symbolrunner finns via `--elf-file/--elf-symbol` (plus `--elf-size` för `size=0`-symboler) och patchar out-of-range `B/BL` till lokala returstubbar.
- ELF-symbolrunnern stöder nu även importspecifika returstubbar via `--elf-import-stub <symbol=value>` baserat på `.rela.plt/.plt`.
- ELF-symbolrunnern stöder nu även host-callbacks via `--elf-import-callback <symbol=op>` (t.ex. `ret_x0..ret_x7`, `add_x0_x1`, `sub_x0_x1`, `ret_sp`, `nonnull_x0`, `guest_alloc_x0`, `guest_free_x0`, `guest_calloc_x0_x1`, `guest_realloc_x0_x1`, `guest_memcpy_x0_x1_x2`, `guest_memset_x0_x1_x2`, `guest_memcmp_x0_x1_x2`, `guest_memmove_x0_x1_x2`, `guest_strnlen_x0_x1`, `guest_strlen_x0`, `guest_strcmp_x0_x1`, `guest_strncmp_x0_x1_x2`, `guest_strcpy_x0_x1`, `guest_strncpy_x0_x1_x2`, `guest_strchr_x0_x1`) via interna callback-markörer.
- ELF-importmappning läser nu både `REL` och `RELA` från `.rel[a].plt/.rel[a].iplt` samt sektioner som pekar på `.plt/.plt.sec`.
- ELF-symbolrunnern kan nu skriva per-symbol patchspårning med `--elf-import-trace <path>`.
- PoC kör lokala regressionstargets (`make run-*`) stabilt, inklusive nya SP-fall.
- Opcode-inventering finns nu via `make run-opcode-inventory` (senaste rapport:
  `reports/opcode_inventory_20260212_202130.txt`).
- Mnemonic-inventering finns nu via `make run-mnemonic-inventory` (senaste rapport:
  `reports/mnemonic_inventory_20260212_202242.txt`).
- Efter stöd för W-former, logical-immediate, `UBFM`, `ADDS/SUBS (imm)` (inkl.
  `SP/WSP` i källregister, `CMN/CMP`-alias), `CSEL (W)`,
  `UDIV/SDIV`, multiply-familjen (`UMADDL/UMSUBL/SMADDL/SMSUBL`, `MADD/MSUB`) och
  variabla shift-familjen (`LSLV/LSRV/ASRV/RORV`) samt register-offset minnesformer
  (`STR/LDR X/W`, `STRB/H/LDRB/H`, både unsigned/signed extend) samt HINT-rymden
  (`D5032xxF`, no-op i PoC) + enkel `MRS`-stub (`0xD52...` -> `0`) + conditional-select-
  familjen (`CSEL/CSINC/CSINV/CSNEG`, inkl. `CSET/CSETM`-alias och `WZR/XZR` i källor) +
  `MOVN` (W/X) + `MOVZ/MOVN/MOVK` med write-discard till `WZR/XZR` + reg-offset-
  ALU extended-register (`ADD/SUB` för `X/W`, inkl. `UXTB/UXTH/UXTW/UXTX` och
  `SXTB/SXTH/SXTW/SXTX`, shift `0..4`, samt `SP/WSP`-alias i `Rd/Rn` + `Rm = WZR/XZR`) +
  flaggsättande extended-register varianter
  (`ADDS/SUBS`, inkl. `CMN/CMP`-alias via `WZR/XZR` och `WZR/XZR` i källor) +
  flaggsättande shifted-register
  varianter (`ADDS/SUBS` för `X/W`, inkl. `CMN/CMP`-alias) + logical shifted-register
  utan flaggsättning (`AND/BIC` för `X/W`, med bevarad NZCV) +
  `ADD/SUB` shifted-register med `Rm = WZR/XZR` (`W/X`) samt `SP/WSP`-alias i `Rd/Rn` +
  logical shifted-register med `ZR`-källor och write-discard (`ORR/EOR` för `X/W`,
  `ANDS/BICS/CMP` för `X/W`, inkl. `MOV`-alias via `ORR ... , ZR, ...`) +
  maskfix (`...0800`/`...0C00`) + SIMD/FP minnesformer för `Q` (`LDR/STR` unsigned imm,
  `LDUR/STUR` + post/pre-index + `LDP/STP` offset + post/pre-index) + SIMD-logik
  (`AND/BIC/ORR/EOR` för `Vd.{8B,16B}`) + SIMD-immediate (`MOVI 8B/16B`, `MOVI 2D`
  för `#0/#-1`) + SIMD aritmetik (`SQRDMLAH 2S/4S`) + `ORN/MVN` (shifted register) +
  `EXTR/ROR` (imm) + `CCMP/CCMN` (reg/imm, `W/X`) + `FCMP/FCMPE` (`S/D`, reg+imm0) +
  `FADD/FSUB/FMUL/FDIV` (`S/D`) + `FMOV` (GPR<->FP) + `SCVTF/UCVTF` + `FCVTZS/FCVTZU` +
  `FCCMP/FCCMPE` (`S/D`) ligger inventerings-täckningen nu på ~85.12%
  (från ~53.42% i tidig baseline).

## Fas 1: Utöka ISA-stöd

- Lägg till `MOVK`, `ADR/ADRP`, `LDR/STR`, `B/BL`, `CBZ/CBNZ`, `TBZ/TBNZ`.
- Lägg till komplett registerfil (`x0..x30`, `sp`, `pc`, `nzcv`).
- Lägg till minnesåtkomst med korrekt alignment- och endian-hantering.

## Fas 2: Runtime

- Implementera block-cache för översatta basic blocks.
- Lägg till direct block chaining och invalidation.
- Lägg till signal/exception-översättning.

## Fas 3: Android integration

- Implementera ett bibliotek som följer Android NativeBridge API.
- Hooka `dlopen/dlsym` för ARM64 `.so` och route till translator-runtime.
- Implementera trampoliner mellan ART/JNI och översatt kod.

## Fas 4: Spelkompatibilitet

- Breddat NEON/SIMD-stöd (ALU + fler adressformer; `Q` load/store + pair finns nu).
- TLS, futex och tråd-synchronisering.
- Syscall- och libc-kantfall.
- Optimering av hot paths (register allocation, peephole, inline caches).

## Rekommenderad prioritet härnäst

1. Finslipa FP-semantik: FP-undantag/rounding-mode samt NaN/out-of-range-beteende i konverteringar.
2. Bygg vidare på SIMD/NEON-bredd (arith, permute, compare) utifrån inventory-topplistor.
3. Bygg nästa ELF-lager ovanpå callback/trace-flödet: fler libc-lika callback-op:s (`strrchr`, `strstr`, `snprintf`-shim), bättre argument/retur-semantik och fallback-policy när symbolmappning saknas.

## Bedömning

Det här är ett större projekt. För att nå "spelbart" läge snabbare är det bäst
att återanvända en existerande DBT-backend och bygga NativeBridge-lagret ovanpå den.
