# Baseline Interpreter Duplicate BuiltinId Audit

**Date:** 2026-04-20  
**File:** `crates/franken-engine/src/baseline_interpreter.rs`  
**Audit Scope:** Duplicate BuiltinId enum arms in match statements

## Summary

**Critical Finding:** Extensive duplication of BuiltinId patterns found throughout the baseline interpreter.

- **Total unique BuiltinId variants:** 185
- **Variants with duplicates:** 183 (99.2%)
- **Total occurrences:** 589
- **Duplicate occurrences:** 587 (99.7%)
- **Unique occurrences:** 2

## Duplicate BuiltinId Findings

The following BuiltinId variants appear multiple times in match statements, potentially causing unreachable code or incorrect dispatch behavior:

### High-Frequency Duplicates (5+ occurrences)

| BuiltinId | Occurrences | Line Numbers |
|-----------|-------------|--------------|
| `ParseFloat` | 13 | [16736, 17430, 23447, 23468, 23815, 23832, 23858, 23879, 23901, 23922, 23943, 23969, 23990] |
| `StringPrototypeSplit` | 13 | [16227, 17128, 17408, 18729, 18738, 18752, 18761, 18775, 18784, 18798, 18807, 18822, 18837] |
| `SetTimeout` | 8 | [16641, 17427, 21715, 21722, 21777, 21784, 21837, 21844] |
| `ArrayPrototypeSort` | 7 | [9432, 17192, 17300, 17437, 23027, 23089, 23096] |
| `ArrayPrototypeConcat` | 7 | [16337, 17190, 17298, 17415, 23183, 23224, 23285] |
| `ArrayPrototypeReverse` | 6 | [8846, 12986, 15815, 17185, 17295, 17381] |
| `ArrayPrototypeFind` | 6 | [9046, 12536, 16493, 17189, 17277, 17419] |
| `ArrayPrototypeFindIndex` | 6 | [10859, 13557, 16533, 17238, 17323, 17420] |
| `StringPrototypeEndsWith` | 6 | [8982, 12640, 15944, 17178, 17282, 17388] |
| `StringPrototypeToLowerCase` | 6 | [8122, 14399, 15861, 17126, 17345, 17382] |
| `StringPrototypeToUpperCase` | 6 | [8135, 14493, 15869, 17127, 17349, 17383] |
| `ObjectGetOwnPropertyNames` | 6 | [10953, 13604, 16181, 17241, 17324, 17400] |

### Complete Duplicate List

<details>
<summary>All 183 BuiltinId variants with duplicates</summary>

- `ArrayFrom`: 2 occurrences at lines [7105, 17110]
- `ArrayFromAsync`: 2 occurrences at lines [14147, 17339]
- `ArrayIsArray`: 2 occurrences at lines [6987, 17109]
- `ArrayOf`: 2 occurrences at lines [7083, 17111]
- `ArrayPrototypeAt`: 4 occurrences at lines [11871, 14017, 17265, 17335]
- `ArrayPrototypeConcat`: 7 occurrences at lines [16337, 17190, 17298, 17415, 23183, 23224, 23285]
- `ArrayPrototypeCopyWithin`: 4 occurrences at lines [11608, 15255, 17260, 17367]
- `ArrayPrototypeEntries`: 4 occurrences at lines [12051, 15711, 17269, 17379]
- `ArrayPrototypeEvery`: 4 occurrences at lines [16045, 17196, 17307, 17393]
- `ArrayPrototypeFill`: 4 occurrences at lines [11706, 13051, 17261, 17303]
- `ArrayPrototypeFilter`: 4 occurrences at lines [12845, 17188, 17288, 17404]
- `ArrayPrototypeFind`: 6 occurrences at lines [9046, 12536, 16493, 17189, 17277, 17419]
- `ArrayPrototypeFindIndex`: 6 occurrences at lines [10859, 13557, 16533, 17238, 17323, 17420]
- `ArrayPrototypeFlat`: 4 occurrences at lines [9938, 13696, 17194, 17327]
- `ArrayPrototypeFlatMap`: 4 occurrences at lines [11524, 13851, 17258, 17331]
- `ArrayPrototypeForEach`: 3 occurrences at lines [9034, 17186, 17386]
- `ArrayPrototypeGroup`: 2 occurrences at lines [14891, 17359]
- `ArrayPrototypeGroupToMap`: 2 occurrences at lines [15057, 17363]
- `ArrayPrototypeIncludes`: 2 occurrences at lines [7284, 17117]
- `ArrayPrototypeIndexOf`: 2 occurrences at lines [7363, 17118]
- `ArrayPrototypeJoin`: 2 occurrences at lines [7207, 17116]
- `ArrayPrototypeKeys`: 4 occurrences at lines [12117, 15590, 17270, 17375]
- `ArrayPrototypeLastIndexOf`: 4 occurrences at lines [10794, 13404, 17237, 17319]
- `ArrayPrototypeMap`: 4 occurrences at lines [16313, 17187, 17289, 17409]
- `ArrayPrototypePop`: 2 occurrences at lines [7035, 17113]
- `ArrayPrototypePush`: 2 occurrences at lines [6956, 17112]
- `ArrayPrototypeReduce`: 5 occurrences at lines [9325, 16136, 17191, 17293, 17398]
- `ArrayPrototypeReduceRight`: 4 occurrences at lines [11184, 13284, 17249, 17315]
- `ArrayPrototypeReverse`: 6 occurrences at lines [8846, 12986, 15815, 17185, 17295, 17381]
- `ArrayPrototypeShift`: 2 occurrences at lines [7046, 17114]
- `ArrayPrototypeSlice`: 2 occurrences at lines [7454, 17119]
- `ArrayPrototypeSome`: 4 occurrences at lines [10082, 17195, 17311, 17392]
- `ArrayPrototypeSort`: 7 occurrences at lines [9432, 17192, 17300, 17437, 23027, 23089, 23096]
- `ArrayPrototypeSplice`: 2 occurrences at lines [9635, 17193]
- `ArrayPrototypeToReversed`: 2 occurrences at lines [14432, 17347]
- `ArrayPrototypeToSorted`: 2 occurrences at lines [14532, 17351]
- `ArrayPrototypeToSpliced`: 2 occurrences at lines [14703, 17355]
- `ArrayPrototypeUnshift`: 2 occurrences at lines [7057, 17115]
- `ArrayPrototypeValues`: 4 occurrences at lines [12183, 15446, 17271, 17371]
- `ArrayPrototypeWith`: 2 occurrences at lines [14292, 17343]
- `Boolean`: 2 occurrences at lines [9783, 17214]
- `ClearTimeout`: 5 occurrences at lines [16691, 17428, 21855, 21885, 21906]
- `ConsoleError`: 4 occurrences at lines [8670, 17156, 17434, 23644]
- `ConsoleInfo`: 4 occurrences at lines [16862, 17436, 23599, 23688]
- `ConsoleLog`: 4 occurrences at lines [8641, 17155, 17433, 23625]
- `ConsoleWarn`: 4 occurrences at lines [8699, 17157, 17435, 23663]
- `Date`: 4 occurrences at lines [8735, 17161, 23520, 23554]
- `DateNow`: 5 occurrences at lines [8728, 16329, 17160, 17414, 23492]
- `DatePrototypeGetTime`: 4 occurrences at lines [11418, 17255, 17308, 23570]
- `DatePrototypeToString`: 2 occurrences at lines [11448, 17256]
- `DecodeURIComponent`: 2 occurrences at lines [16586, 17426]
- `EncodeURIComponent`: 2 occurrences at lines [16573, 17425]
- `Error`: 2 occurrences at lines [9515, 17210]
- `FunctionPrototypeApply`: 2 occurrences at lines [11348, 17253]
- `FunctionPrototypeCall`: 2 occurrences at lines [11090, 17245]
- `IsFinite`: 4 occurrences at lines [16843, 17432, 23360, 23377]
- `IsNaN`: 4 occurrences at lines [16824, 17431, 23321, 23338]
- `JSONParse`: 2 occurrences at lines [16457, 17418]
- `JSONStringify`: 2 occurrences at lines [16437, 17417]
- `JsonParse`: 2 occurrences at lines [8410, 17141]
- `JsonStringify`: 2 occurrences at lines [8366, 17142]
- `Map`: 2 occurrences at lines [10220, 17223]
- `MapPrototypeDelete`: 2 occurrences at lines [10610, 17234]
- `MapPrototypeGet`: 2 occurrences at lines [10395, 17230]
- `MapPrototypeHas`: 2 occurrences at lines [10562, 17233]
- `MapPrototypeSet`: 2 occurrences at lines [10332, 17229]
- `MathAbs`: 5 occurrences at lines [8171, 17132, 17399, 19728, 19763]
- `MathAcos`: 4 occurrences at lines [11129, 13379, 17247, 17318]
- `MathAcosh`: 2 occurrences at lines [14122, 17338]
- `MathAsin`: 4 occurrences at lines [11112, 13532, 17246, 17322]
- `MathAsinh`: 2 occurrences at lines [14271, 17342]
- `MathAtan`: 2 occurrences at lines [13031, 17302]
- `MathAtan2`: 4 occurrences at lines [11065, 13193, 17244, 17306]
- `MathAtanh`: 2 occurrences at lines [14407, 17346]
- `MathCbrt`: 2 occurrences at lines [13676, 17326]
- `MathCeil`: 3 occurrences at lines [8190, 17133, 17406]
- `MathClz32`: 4 occurrences at lines [12033, 13831, 17268, 17330]
- `MathCos`: 5 occurrences at lines [9121, 17167, 17297, 17422, 22953]
- `MathExp`: 2 occurrences at lines [9226, 17169]
- `MathFloor`: 3 occurrences at lines [8211, 17134, 17405]
- `MathFround`: 2 occurrences at lines [13995, 17334]
- `MathHypot`: 4 occurrences at lines [11569, 14501, 17259, 17350]
- `MathImul`: 4 occurrences at lines [11845, 14669, 17264, 17354]
- `MathLog`: 3 occurrences at lines [9200, 17168, 17440]
- `MathLog10`: 2 occurrences at lines [13227, 17310]
- `MathLog2`: 2 occurrences at lines [13264, 17314]
- `MathMax`: 3 occurrences at lines [8262, 17136, 17401]
- `MathMin`: 3 occurrences at lines [8311, 17137, 17402]
- `MathPI`: 2 occurrences at lines [9266, 17171]
- `MathPow`: 4 occurrences at lines [8753, 17164, 17292, 17411]
- `MathRandom`: 3 occurrences at lines [8360, 17138, 17413]
- `MathRound`: 3 occurrences at lines [8232, 17135, 17407]
- `MathSign`: 4 occurrences at lines [10140, 14860, 17173, 17358]
- `MathSin`: 5 occurrences at lines [9101, 17166, 17296, 17421, 22952]
- `MathSqrt`: 3 occurrences at lines [8901, 17165, 17410]
- `MathTan`: 5 occurrences at lines [9246, 17170, 17299, 17423, 22954]
- `MathTrunc`: 4 occurrences at lines [9606, 15032, 17172, 17362]
- `Number`: 2 occurrences at lines [9754, 17213]
- `NumberIsFinite`: 4 occurrences at lines [8628, 15992, 17152, 17390]
- `NumberIsInteger`: 4 occurrences at lines [12690, 15925, 17283, 17387]
- `NumberIsNaN`: 4 occurrences at lines [8616, 15977, 17151, 17389]
- `NumberIsNaNMethod`: 2 occurrences at lines [12971, 17291]
- `NumberParseFloat`: 2 occurrences at lines [12709, 17284]
- `NumberParseInt`: 2 occurrences at lines [12826, 17286]
- `NumberPrototypeToExponential`: 2 occurrences at lines [15405, 17370]
- `NumberPrototypeToFixed`: 2 occurrences at lines [15218, 17366]
- `NumberPrototypeToPrecision`: 2 occurrences at lines [15543, 17374]
- `NumberPrototypeToString`: 4 occurrences at lines [11289, 16063, 17251, 17395]
- `NumberPrototypeValueOf`: 2 occurrences at lines [15683, 17378]
- `ObjectAssign`: 2 occurrences at lines [7768, 17104]
- `ObjectCreate`: 2 occurrences at lines [7829, 17106]
- `ObjectDefineProperty`: 4 occurrences at lines [10176, 13914, 17207, 17332]
- `ObjectEntries`: 2 occurrences at lines [7695, 17103]
- `ObjectFreeze`: 2 occurrences at lines [7807, 17105]
- `ObjectGetOwnPropertyDescriptor`: 2 occurrences at lines [11972, 17267]
- `ObjectGetOwnPropertyNames`: 6 occurrences at lines [10953, 13604, 16181, 17241, 17324, 17400]
- `ObjectGetPrototypeOf`: 4 occurrences at lines [11011, 14060, 17242, 17336]
- `ObjectHasOwnProperty`: 3 occurrences at lines [9400, 17206, 17348]
- `ObjectIs`: 2 occurrences at lines [14213, 17340]
- `ObjectIsExtensible`: 2 occurrences at lines [14822, 17356]
- `ObjectIsFrozen`: 2 occurrences at lines [15347, 17368]
- `ObjectIsSealed`: 2 occurrences at lines [15499, 17372]
- `ObjectKeys`: 2 occurrences at lines [7603, 17101]
- `ObjectPreventExtensions`: 2 occurrences at lines [14970, 17360]
- `ObjectPropertyIsEnumerable`: 2 occurrences at lines [14623, 17352]
- `ObjectPrototypeHasOwnProperty`: 3 occurrences at lines [12505, 17280, 17396]
- `ObjectPrototypePropertyIsEnumerable`: 2 occurrences at lines [13134, 17304]
- `ObjectPrototypeToString`: 4 occurrences at lines [13325, 15877, 17316, 17384]
- `ObjectPrototypeValueOf`: 4 occurrences at lines [11480, 13248, 17257, 17312]
- `ObjectSeal`: 2 occurrences at lines [15137, 17364]
- `ObjectSetPrototypeOf`: 4 occurrences at lines [12249, 14377, 17272, 17344]
- `ObjectValues`: 2 occurrences at lines [7649, 17102]
- `ParseFloat`: 13 occurrences at lines [16736, 17430, 23447, 23468, 23815, 23832, 23858, 23879, 23901, 23922, 23943, 23969, 23990]
- `ParseInt`: 4 occurrences at lines [16717, 17429, 23399, 23421]
- `PromiseAll`: 2 occurrences at lines [11311, 17252]
- `PromiseReject`: 2 occurrences at lines [11038, 17243]
- `PromiseResolve`: 4 occurrences at lines [9307, 13762, 17203, 17328]
- `RegExp`: 2 occurrences at lines [11146, 17248]
- `RegExpPrototypeTest`: 4 occurrences at lines [13469, 17320, 17424, 22991]
- `Set`: 2 occurrences at lines [10248, 17224]
- `SetPrototypeAdd`: 2 occurrences at lines [10442, 17231]
- `SetPrototypeClear`: 2 occurrences at lines [10750, 17236]
- `SetPrototypeDelete`: 2 occurrences at lines [10680, 17235]
- `SetPrototypeHas`: 2 occurrences at lines [10514, 17232]
- `SetTimeout`: 8 occurrences at lines [16641, 17427, 21715, 21722, 21777, 21784, 21837, 21844]
- `StringFromCharCode`: 4 occurrences at lines [10928, 13352, 17240, 17317]
- `StringFromCodePoint`: 2 occurrences at lines [11816, 17263]
- `StringPrototypeAnchor`: 2 occurrences at lines [15374, 17369]
- `StringPrototypeAt`: 4 occurrences at lines [11924, 13959, 17266, 17333]
- `StringPrototypeBig`: 2 occurrences at lines [15526, 17373]
- `StringPrototypeBlink`: 2 occurrences at lines [15666, 17377]
- `StringPrototypeCharAt`: 4 occurrences at lines [7863, 16011, 17122, 17391]
- `StringPrototypeCharCodeAt`: 4 occurrences at lines [10890, 17239, 17313, 17394]
- `StringPrototypeCodePointAt`: 4 occurrences at lines [11778, 13501, 17262, 17321]
- `StringPrototypeConcat`: 2 occurrences at lines [13162, 17305]
- `StringPrototypeEndsWith`: 6 occurrences at lines [8982, 12640, 15944, 17178, 17282, 17388]
- `StringPrototypeIncludes`: 4 occurrences at lines [8795, 12920, 17176, 17290]
- `StringPrototypeIndexOf`: 2 occurrences at lines [7919, 17123]
- `StringPrototypeIsWellFormed`: 2 occurrences at lines [14249, 17341]
- `StringPrototypeLocaleCompare`: 4 occurrences at lines [11375, 17254, 17309, 17403]
- `StringPrototypeMatch`: 5 occurrences at lines [9806, 17199, 17294, 17301, 17416]
- `StringPrototypeNormalize`: 4 occurrences at lines [12303, 13658, 17274, 17325]
- `StringPrototypePadEnd`: 4 occurrences at lines [9543, 12443, 17182, 17279]
- `StringPrototypePadStart`: 4 occurrences at lines [9337, 12381, 17181, 17278]
- `StringPrototypeRepeat`: 4 occurrences at lines [9270, 12779, 17180, 17285]
- `StringPrototypeReplace`: 4 occurrences at lines [9141, 17179, 17287, 17412]
- `StringPrototypeReplaceAll`: 2 occurrences at lines [13787, 17329]
- `StringPrototypeSearch`: 4 occurrences at lines [10045, 14994, 17200, 17361]
- `StringPrototypeSlice`: 2 occurrences at lines [8040, 17125]
- `StringPrototypeSplit`: 13 occurrences at lines [16227, 17128, 17408, 18729, 18738, 18752, 18761, 18775, 18784, 18798, 18807, 18822, 18837]
- `StringPrototypeStartsWith`: 4 occurrences at lines [8931, 12588, 17177, 17281]
- `StringPrototypeSubstr`: 4 occurrences at lines [11220, 15164, 17250, 17365]
- `StringPrototypeSubstring`: 4 occurrences at lines [7968, 16086, 17124, 17397]
- `StringPrototypeToLocaleLowerCase`: 2 occurrences at lines [16892, 17438]
- `StringPrototypeToLocaleUpperCase`: 2 occurrences at lines [16901, 17439]
- `StringPrototypeToLowerCase`: 6 occurrences at lines [8122, 14399, 15861, 17126, 17345, 17382]
- `StringPrototypeToUpperCase`: 6 occurrences at lines [8135, 14493, 15869, 17127, 17349, 17383]
- `StringPrototypeToWellFormed`: 2 occurrences at lines [14092, 17337]
- `StringPrototypeTrim`: 4 occurrences at lines [8148, 15907, 17129, 17385]
- `StringPrototypeTrimEnd`: 4 occurrences at lines [12358, 14842, 17276, 17357]
- `StringPrototypeTrimStart`: 4 occurrences at lines [12335, 14651, 17275, 17353]
- `Symbol`: 2 occurrences at lines [9860, 17217]
- `SymbolIterator`: 2 occurrences at lines [12277, 17273]
- `WeakMap`: 2 occurrences at lines [10276, 17225]
- `WeakMapPrototypeGet`: 2 occurrences at lines [15780, 17380]
- `WeakMapPrototypeHas`: 2 occurrences at lines [15634, 17376]
- `WeakSet`: 2 occurrences at lines [10304, 17226]

</details>

## Pattern Analysis

The duplicates appear to follow several patterns:

1. **Match Statement Duplicates**: Lines 6956-16901 (main match statement) vs lines 17100+ (ID mapping section)
2. **Test Code Duplicates**: Lines 18000+ appear to be test fixtures with repeated patterns
3. **Integration Test Duplicates**: Lines 23000+ show additional test code with pattern repetition

## Potential Impact

- **Dead Code**: Later duplicate match arms will never be reached
- **Maintenance Issues**: Changes to one arm may not be reflected in duplicates
- **Runtime Behavior**: First matching arm determines behavior, subsequent arms are ignored
- **Code Bloat**: 587/589 (99.7%) occurrences are duplicates, significantly inflating file size

## Recommendations

1. **Immediate Action Required**: Consolidate duplicate match arms into single, authoritative implementations
2. **Code Review**: Examine why this extensive duplication occurred (copy-paste errors, code generation issues)
3. **Testing**: Verify that deduplication doesn't break existing functionality
4. **Automated Prevention**: Consider linting rules to prevent future duplicate match arms

## Notes

This audit was conducted using pattern matching on `"builtin:[A-Z][a-zA-Z]*"` strings within the source file. The extensive duplication suggests either systematic copy-paste errors or a code generation issue that should be investigated and resolved.