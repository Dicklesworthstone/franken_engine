var text = '\uD800a😀\uDC00';
var elements = Array.from(text);
var joined = '';
for (var i = 0; i < elements.length; i++) joined += elements[i];
elements.length === 4 && elements[0].charCodeAt(0) === 55296 &&
elements[1] === 'a' && elements[2] === '😀' && elements[2].length === 2 &&
elements[3].charCodeAt(0) === 56320 && joined === text &&
Array.from('ABC').length === 3 && Array.from('').length === 0 &&
'abc' < 'abd' && 'a' < 'ab' && '😀' < '\uFF5A';
