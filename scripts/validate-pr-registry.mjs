import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
// The registry is a historical record written when the repository lived under its original owner. The repository was
// transferred, so CI may run under the current organization: the repository NAME must still match exactly
// (case-insensitively, as GitHub treats it) and the owner must be the recorded one or the known successor.
const recorded = JSON.parse(body).repository;
const SUCCESSOR_OWNERS = new Map([['neophilism', ['justice-for-all-movement']]]);
const current = process.env.GITHUB_REPOSITORY;
if (current && current !== recorded) {
  const [recordedOwner, recordedName] = String(recorded).toLowerCase().split('/');
  const [owner, name, ...rest] = current.toLowerCase().split('/');
  if (rest.length || name !== recordedName || !(SUCCESSOR_OWNERS.get(recordedOwner) ?? []).includes(owner))
    throw new Error(`PR registry belongs to ${recorded}, not ${current}`);
}
const repository = recorded;
const {document} = parsePrRegistry(body, repository);
const retired = JSON.parse(await readFile(new URL('../registry/roadmap.json', import.meta.url), 'utf8'));
if (retired.repository !== repository || retired.deprecated !== true || retired.redirectTo !== 'registry/prs.json' ||
    Object.hasOwn(retired, 'milestones') || Object.hasOwn(retired, 'units') || Object.hasOwn(retired, 'plannedPrCount'))
  throw new Error('Only registry/prs.json may contain the active PR plan');
console.log(`Valid PR registry: ${repository}, ${document.units.length} approved units; runtime acceptance is separate.`);
