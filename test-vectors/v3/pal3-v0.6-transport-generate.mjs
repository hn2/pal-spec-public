// Generates pal3-v0.6-transport-vectors.json: the mailbox location key of section 14.6.
// Standalone, Node built-ins only. Run: node test-vectors/v3/pal3-v0.6-transport-generate.mjs
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const locationKey = (recipientPublicKey, dayIndex) =>
  createHash('sha256').update(`palexplorer-mailbox-v1\n${recipientPublicKey}\n${dayIndex}`, 'utf8').digest('hex');

const recipientPublicKey = 'ab'.repeat(32);
const unixSeconds = Date.parse('2026-11-15T12:00:00Z') / 1000;
const dayIndex = Math.floor(unixSeconds / 86400);

const out = {
  specVersion: '3.0.0-draft.6.10',
  description: 'Chat mailbox location key (section 14.6): SHA-256 of the UTF-8 string palexplorer-mailbox-v1, a line feed, the recipient public key as 64 lowercase hexadecimal characters, a line feed and the day index in decimal digits.',
  mailboxLocationKey: {
    recipientPublicKey,
    unixSeconds,
    dayIndex,
    inputUtf8: `palexplorer-mailbox-v1\n${recipientPublicKey}\n${dayIndex}`,
    locationKeyHex: locationKey(recipientPublicKey, dayIndex),
  },
};

writeFileSync(new URL('./pal3-v0.6-transport-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
