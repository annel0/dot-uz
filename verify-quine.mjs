import { lzqDecodeFragment } from './doturl-core.mjs';
const fragment = 'CBAcaHR0cHM6Ly94bi0tcm9oLnV6LyNDLAiBAcaHR0cHM6Ly94bi0tcm9oLnV6LyNDLAiRAiLADRAiLADLADLAMRAiLADLADLAMRAMLAMRAMLAMRAMLAMRAMLAMRAMLAALAALADRAMLAALAALADRADRAD';
const url = `https://xn--roh.uz/#${fragment}`;
const decoded = lzqDecodeFragment(fragment);
console.log(decoded);
console.log('fixed_point =', decoded === url);
if (decoded !== url) process.exit(1);
