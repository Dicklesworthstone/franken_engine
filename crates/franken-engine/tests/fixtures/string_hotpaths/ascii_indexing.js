var alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
var text = '';
for (var repeat = 0; repeat < 16; repeat++) text += alphabet;
var expected = 0;
for (var a = 0; a < alphabet.length; a++) expected += alphabet.charCodeAt(a);
var total = 0;
var indexed = '';
for (var i = 0; i < text.length; i++) {
    total += text.charCodeAt(i);
    total += text.codePointAt(i);
    indexed += text[i];
}
text.length === 992 && total === expected * 32 && indexed === text &&
text.charAt(2147483647) === '' && text.codePointAt(2147483647) === undefined;
