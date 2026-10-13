var text = 'a\uD83D\uDE00é中\uD800b\uDC00';
var high = text.charAt(1);
var low = text.charAt(2);
var healed = high + low;
text.length === 8 && text.charCodeAt(1) === 55357 && text.charCodeAt(2) === 56832 &&
text.codePointAt(1) === 128512 && text.codePointAt(2) === 56832 &&
text.charCodeAt(5) === 55296 && text.charCodeAt(7) === 56320 &&
healed === '😀' && healed.length === 2 &&
('' + text).length === 8 && (text + '').length === 8 &&
text.charAt(2147483647) === '' && text.codePointAt(2147483647) === undefined;
