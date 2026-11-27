// The extension's background script: the verifier, wired to this browser.
/* eslint-disable @typescript-eslint/no-explicit-any */
import { install } from './background.js';

declare const browser: any;
declare const chrome: any;

install(typeof browser !== 'undefined' ? browser : chrome);
