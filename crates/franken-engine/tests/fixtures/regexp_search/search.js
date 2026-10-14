var pattern = 'needle' + '()'.repeat(1024) + '(?=)';
var text = 'x'.repeat(16384) + 'needle';
var result = new RegExp(pattern).exec(text);
console.log(result.index, result[0], result.length, result[1], result[1024]);
var cases = [
  ['(a)b|c','abc'],
  ['(?=(a+))a*b\\1','baaabac'],
  ['(.*?)a(?!(a+)b\\2c)\\2(.*)','baaabaac'],
  ['(?:(a)|(b))+c','xxababc'],
  ['(?<=((a)|(b))+)(c)','xxababc'],
  ['(?!(a+))b|(?=(c))c','aabc'],
  ['a(?=(b))c|b','ab'],
  ['(?=(a(?=(b))))ac|b','ab'],
  ['(?<name>a)\\k<name>|b','xaaab'],
  ['(?<=(\\d+)(\\d+))$','1053']
];
for (var i=0;i<cases.length;i++) {
 var match = new RegExp(cases[i][0]).exec(cases[i][1]);
 console.log(match.index, JSON.stringify(Array.from(match)));
}
var global = /(a)b|c/g;
var all = []; var m;
while ((m=global.exec('abcabc')) !== null) all.push([m.index,Array.from(m)]);
console.log(JSON.stringify(all), global.lastIndex);
var sticky = /n()(?!x)/y;
sticky.lastIndex=1; console.log(sticky.exec('xnxn'),sticky.lastIndex);
sticky.lastIndex=3; var last = sticky.exec('xnxn');console.log(last.index,JSON.stringify(Array.from(last)),sticky.lastIndex);
