function referenceIndex(text, needle, from, last) {
    var start = from > text.length ? text.length : from;
    if (needle.length === 0) return start;
    var found = -1;
    for (var i = 0; i + needle.length <= text.length; i++) {
        var equal = true;
        for (var j = 0; j < needle.length; j++) {
            if (text.charCodeAt(i + j) !== needle.charCodeAt(j)) equal = false;
        }
        if (equal) {
            if (!last && i >= start) return i;
            if (last && i <= start) found = i;
        }
    }
    return found;
}
var texts = ['', 'aaaaa', 'abababa', 'abc\u0000abc', 'a😀b😀', '\uD800a\uDC00', 'é😀é😀', '中aé中aé', '😀a😀a😀'];
var needles = ['', 'a', 'aaa', 'aba', '\u0000', '😀', '\uD83D', '\uDE00', '\uD800', 'é', 'é😀', '😀a😀', '中aé'];
var offsets = [0, 1, 2, 3, 4, 5, 6, 2147483647];
var ok = true;
for (var t = 0; t < texts.length; t++) {
    for (var n = 0; n < needles.length; n++) {
        for (var p = 0; p < offsets.length; p++) {
            if (texts[t].indexOf(needles[n], offsets[p]) !== referenceIndex(texts[t], needles[n], offsets[p], false)) ok = false;
            if (texts[t].lastIndexOf(needles[n], offsets[p]) !== referenceIndex(texts[t], needles[n], offsets[p], true)) ok = false;
        }
    }
}
ok;
