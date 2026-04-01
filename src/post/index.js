import core from '@actions/core';
import exec from '@actions/exec';
import fs from 'fs';
import path from 'path';
import * as http from '@actions/http-client';
import { BlobServiceClient, StorageSharedKeyCredential } from '@azure/storage-blob';
import { DefaultArtifactClient } from '@actions/artifact';
import {
    parseSBOMEntries,
    isSBOMEnabled,
    writeSBOMSummary,
} from './sbom-summary.js';

const CIMON_SCRIPT_DOWNLOAD_URL =
    'https://raw.githubusercontent.com/RemakingEden/cimon-releases/main/install.sh';
const CIMON_SCRIPT_PATH = '/tmp/install.sh';
const CIMON_EXECUTABLE_DIR = '/tmp/cimon';
const CIMON_EXECUTABLE_PATH = '/tmp/cimon/cimon';

// Matches lines like: name(pid) [ command ]
// Both name and command are optional — cimon emits bare (pid) nodes for shell internals
const PROCESS_TREE_LINE = /^(\s*)([\w][\w.-]*)?\((\d+)\)(?:\s*\[\s*(.*?)\s*\])?\s*$/;

const httpClient = new http.HttpClient('cimon-action');

function getActionConfig() {
    return {
        cimon: {
            logLevel: core.getInput('log-level'),
        },
        soc: {
            storageAccount: core.getInput('soc-storage-account'),
            storageKey: core.getInput('soc-storage-key'),
            container: core.getInput('soc-container'),
            // Future: add sasUrl here and branch in sendToSOC
        },
    };
}

async function run(config) {
    const cimonPath = await resolveCimonPath(config);
    const { output: stopOutput, exitCode } = await stopCimonAgent(cimonPath, config);

    await reportSBOMToGitHub(stopOutput, config);
    await uploadSBOMArtifacts(parseSBOMEntries(stopOutput));

    const jobSummary = readJobSummary();
    const socPayload = buildSOCPayload({ stopOutput, jobSummary, exitCode });
    await sendToSOC(config.soc, socPayload);

    if (exitCode !== 0) {
        throw new Error(`Failed stopping Cimon process: ${exitCode}`);
    }
}

async function resolveCimonPath(config) {
    const savedPath = core.getState('release-path');
    if (savedPath && fs.existsSync(savedPath)) {
        return savedPath;
    }

    if (!fs.existsSync(CIMON_SCRIPT_PATH)) {
        await downloadToFile(CIMON_SCRIPT_DOWNLOAD_URL, CIMON_SCRIPT_PATH);
    }

    if (!fs.existsSync(CIMON_EXECUTABLE_DIR)) {
        const params = [CIMON_SCRIPT_PATH, '-b', CIMON_EXECUTABLE_DIR];
        if (config.cimon.logLevel === 'debug' || config.cimon.logLevel === 'trace') {
            params.push('-d');
        }
        const retval = await exec.exec('sh', params);
        if (retval !== 0) {
            throw new Error(`Failed installing Cimon: ${retval}`);
        }
    }

    return CIMON_EXECUTABLE_PATH;
}

async function stopCimonAgent(cimonPath, config) {
    let output = '';
    const execOptions = {
        env: { ...process.env, CIMON_LOG_LEVEL: config.cimon.logLevel },
        silent: false,
        listeners: {
            stdout: (data) => { output += data.toString(); },
            stderr: (data) => { output += data.toString(); },
        },
        ignoreReturnCode: true,
    };

    const hasSudo = await sudoExists();
    const exitCode = hasSudo
        ? await exec.exec('sudo', ['-E', cimonPath, 'agent', 'stop'], execOptions)
        : await exec.exec(cimonPath, ['agent', 'stop'], execOptions);

    return { output, exitCode };
}

async function reportSBOMToGitHub(stopOutput, config) {
    if (!core.getBooleanInput('report-job-summary')) return;
    const sbomEntries = parseSBOMEntries(stopOutput);
    const sbomEnabled = isSBOMEnabled(stopOutput);
    await writeSBOMSummary(core, sbomEntries, { sbomEnabled });
}

function readJobSummary() {
    try {
        const summaryPath = process.env.GITHUB_STEP_SUMMARY;
        if (summaryPath && fs.existsSync(summaryPath)) {
            return fs.readFileSync(summaryPath, 'utf8');
        }
    } catch (err) {
        core.warning(`SOC: could not read job summary (non-fatal): ${err.message}`);
    }
    return '';
}

function buildSOCPayload({ stopOutput, jobSummary, exitCode }) {
    const processTree = parseProcessTree(jobSummary);

    if (processTree.parseError) {
        core.warning(`SOC: process tree parse issue (non-fatal): ${processTree.parseError}`);
    }

    return {
        healthy: exitCode === 0,
        detectedRisks: parseDetectedRisks(stopOutput),
        repository: process.env.GITHUB_REPOSITORY,
        workflow: process.env.GITHUB_WORKFLOW,
        runId: process.env.GITHUB_RUN_ID,
        runnerOs: process.env.RUNNER_OS,
        imageVersion: process.env.ImageVersion,
        cimonVersion: process.env.CIMON_VERSION,
        networkEvents: parseNetworkEventsFromJobSummary(jobSummary),
        processTree,
        sbomEntries: parseSBOMEntries(stopOutput),
    };
}

async function sendToSOC(socConfig, payload) {
    if (!socConfig.storageAccount || !socConfig.storageKey) return;

    const timestamp = new Date().toISOString().replace(/[:\-T]/g, '').slice(0, 15);
    const blobName = `cimon_${timestamp}.json`;

    try {
        const credential = new StorageSharedKeyCredential(socConfig.storageAccount, socConfig.storageKey);
        const serviceClient = new BlobServiceClient(
            `https://${socConfig.storageAccount}.blob.core.windows.net`,
            credential
        );
        const body = JSON.stringify(payload, null, 2);
        await serviceClient
            .getContainerClient(socConfig.container)
            .getBlockBlobClient(blobName)
            .upload(body, Buffer.byteLength(body), {
                blobHTTPHeaders: { blobContentType: 'application/json' },
            });

        core.info(`SOC: event written to blob storage (${socConfig.container}/${blobName})`);
    } catch (err) {
        core.warning(`SOC: blob upload failed (non-fatal): ${err.message}`);
    }
}

function parseNetworkEventsFromJobSummary(jobSummary) {
    const emptyResult = (parseError) => ({ events: [], parseError });

    if (!jobSummary) return emptyResult(null);

    try {
        const sectionMatch = jobSummary.match(/###\s*TCP\s*\/\s*UDP\s*Events[\s\S]*?(<details[\s\S]*?<\/details>|\|[\s\S]*?)(?=\n#|$)/i);
        if (!sectionMatch) return emptyResult('TCP/UDP events section not found in job summary');

        const tableRows = extractMarkdownTableRows(sectionMatch[0]);
        if (tableRows.length === 0) return emptyResult('No rows found in network events table');

        const { headers, rows } = tableRows;
        const events = rows.map((row) => mapRowToNetworkEvent(headers, row)).filter(Boolean);

        return { events, parseError: null };
    } catch (err) {
        return emptyResult(err.message);
    }
}

function extractMarkdownTableRows(text) {
    const lines = text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('|'));
    if (lines.length < 2) return { headers: [], rows: [] };

    const parseCells = (line) =>
        line.split('|').slice(1, -1).map((cell) => cell.trim());

    const headers = parseCells(lines[0]).map((h) => h.toLowerCase());
    const dataRows = lines.slice(2).map(parseCells);

    return { headers, rows: dataRows };
}

function mapRowToNetworkEvent(headers, cells) {
    const get = (name) => {
        const index = headers.findIndex((h) => h.includes(name));
        return index !== -1 ? cells[index] : null;
    };

    const pid = parseInt(get('pid'), 10);
    if (isNaN(pid)) return null;

    const allowedValue = get('allow');
    const addressValue = get('address') ?? '';
    const [ip, port] = addressValue.includes(':')
        ? addressValue.split(':')
        : [addressValue, null];

    return {
        pid,
        process: get('process'),
        protocol: get('protocol'),
        address: addressValue || null,
        ip: ip || null,
        port: port ? parseInt(port, 10) : null,
        host: get('domain'),
        allowed: allowedValue !== null ? !allowedValue.includes('❌') : null,
    };
}

function parseProcessTree(jobSummary) {
    const emptyResult = (parseError) => ({ nodes: [], raw: null, parseError });

    if (!jobSummary) return emptyResult(null);

    try {
        const sectionMatch = jobSummary.match(/##\s*Process Tree[\s\S]*?```[^\n]*\n([\s\S]*?)```/);
        if (!sectionMatch) {
            return emptyResult('Process tree section or code block not found in job summary');
        }

        const raw = sectionMatch[1];
        const nodes = buildProcessTree(raw);

        if (nodes.length === 0) {
            return { nodes, raw, parseError: 'Process tree parsed but produced no nodes — format may have changed' };
        }

        return { nodes, raw, parseError: null };
    } catch (err) {
        return emptyResult(err.message);
    }
}

function buildProcessTree(raw) {
    const roots = [];
    const stack = [];

    for (const line of raw.split('\n')) {
        if (!line.trim()) continue;

        const match = line.match(PROCESS_TREE_LINE);
        if (!match) continue;

        const [, indent, name, pid, cmd] = match;
        const depth = Math.floor(indent.length / 2);
        const node = {
            pid: parseInt(pid, 10),
            name: name || null,
            cmd: cmd || null,
            children: [],
        };

        while (stack.length > 0 && stack[stack.length - 1].depth >= depth) {
            stack.pop();
        }

        if (stack.length === 0) {
            roots.push(node);
        } else {
            stack[stack.length - 1].node.children.push(node);
        }

        stack.push({ depth, node });
    }

    return roots;
}

function parseDetectedRisks(stopOutput) {
    for (const line of stopOutput.split('\n').reverse()) {
        try {
            const entry = JSON.parse(line.trim());
            if (entry.detectedRisks) return entry.detectedRisks;
        } catch (_) {}
    }
    return null;
}

async function uploadSBOMArtifacts(sbomEntries) {
    if (!sbomEntries || sbomEntries.length === 0) return;

    const filesToUpload = collectSBOMFiles(sbomEntries);

    if (filesToUpload.length === 0) {
        core.info('SBOM: no files to upload as artifacts');
        return;
    }

    const rootDir = resolveSBOMRootDir(filesToUpload);

    try {
        const artifact = new DefaultArtifactClient();
        const { id, size } = await artifact.uploadArtifact(
            'cimon-sbom',
            filesToUpload,
            rootDir,
            { retentionDays: 90 }
        );
        core.info(`SBOM: uploaded ${filesToUpload.length} files as artifact (id=${id}, size=${size})`);
    } catch (err) {
        core.warning(`SBOM: artifact upload failed (non-fatal): ${err.message}`);
    }
}

function collectSBOMFiles(sbomEntries) {
    const files = [];
    for (const entry of sbomEntries) {
        const isTrivial = entry.hasStats
            && entry.components <= 1
            && entry.relationships === 0
            && entry.artifacts === 0;
        if (isTrivial) continue;

        for (const filePath of [entry.cyclonedx, entry.spdx]) {
            if (filePath && fs.existsSync(filePath)) {
                files.push(filePath);
            }
        }
    }

    for (const sbomFile of [...files]) {
        const evidencePath = path.join(path.dirname(sbomFile), 'sbom.evidence.json');
        if (fs.existsSync(evidencePath) && !files.includes(evidencePath)) {
            files.push(evidencePath);
        }
    }

    return files;
}

function resolveSBOMRootDir(filesToUpload) {
    const sbomOutputDir = process.env.CIMON_SBOM_OUTPUT_DIRECTORY;
    if (sbomOutputDir) {
        const normalizedOutputDir = path.resolve(sbomOutputDir);
        const allFilesUnderOutputDir = filesToUpload.every(
            (f) => f.startsWith(normalizedOutputDir + path.sep) || f === normalizedOutputDir
        );
        if (allFilesUnderOutputDir) return normalizedOutputDir;
    }
    return findCommonRoot(filesToUpload);
}

function findCommonRoot(paths) {
    if (paths.length === 0) return '/';
    if (paths.length === 1) return path.dirname(paths[0]);

    const dirs = paths.map((p) => path.dirname(p));
    const segments = dirs[0].split(path.sep);
    let common = '';
    for (let i = 0; i < segments.length; i++) {
        const candidate = segments.slice(0, i + 1).join(path.sep) || path.sep;
        if (dirs.every((d) => d.startsWith(candidate + path.sep) || d === candidate)) {
            common = candidate;
        } else {
            break;
        }
    }
    return common || path.sep;
}

async function sudoExists() {
    try {
        const retval = await exec.exec('sudo', ['-v'], { silent: true });
        return retval === 0;
    } catch {
        return false;
    }
}

async function downloadToFile(url, filePath) {
    const response = await httpClient.get(url);
    const responseBody = await response.readBody();
    fs.writeFileSync(filePath, responseBody);
}

try {
    await run(getActionConfig());
} catch (error) {
    const failOnError = core.getBooleanInput('fail-on-error');
    const reportJobSummary = core.getBooleanInput('report-job-summary');
    if (failOnError) {
        core.setFailed(error.message);
    } else if (reportJobSummary) {
        await core.summary
            .addHeading('Cimon Security Report - Failure')
            .addRaw('Cimon encountered an error and was shut down due to the "fail-on-error=false" flag. Details of the error are below:')
            .addCodeBlock(error.message)
            .write();
    }
}
