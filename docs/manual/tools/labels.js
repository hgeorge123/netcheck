// Parses web/src/i18n/{en,es}.ts into plain objects.
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', '..', '..', 'web', 'src', 'i18n');
function load(lang) {
  const src = fs.readFileSync(`${dir}/${lang}.ts`, 'utf8');
  const out = {};
  const re = /^\s+'([^']+)':\s*(['"`])((?:\\.|(?!\2).)*)\2,?\s*$/gm;
  let m;
  while ((m = re.exec(src))) out[m[1]] = m[3].replace(/\\(['"`\\])/g, '$1');
  return out;
}
module.exports = { en: load('en'), es: load('es') };
