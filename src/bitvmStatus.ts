import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

type AnyObj = Record<string, any>;

export type BitvmStatusQuery = {
  propertyId?: number | string;
  dlcRef?: string;
};

const DEFAULT_ARTIFACTS_DIR = path.resolve(
  process.cwd(),
  '..',
  'UTXORef',
  'UTXO-Ref',
  'bitvm3',
  'utxo_referee',
  'artifacts',
);

const ARTIFACT_FILES = {
  proceduralSync: 'bitvm_procedural_sync_latest.json',
  pipeline: 'm1_pipeline_latest.json',
  parallelUtxoIndex: 'm1_parallel_utxo_index_latest.json',
  challengeBundle: 'm1_challenge_bundle_latest.json',
  draft: 'm1_dlc_draft_latest.json',
} as const;

function artifactsDir(): string {
  return String(process.env.BITVM_REFEREE_ARTIFACTS_DIR || '').trim() || DEFAULT_ARTIFACTS_DIR;
}

function readJson(fileName: string): AnyObj | null {
  const filePath = path.join(artifactsDir(), fileName);
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function str(value: any): string | null {
  const out = String(value ?? '').trim();
  return out ? out : null;
}

function lower(value: any): string | null {
  return str(value)?.toLowerCase() || null;
}

function txid(value: any): string | null {
  const out = lower(value);
  return out && /^[0-9a-f]{64}$/.test(out) ? out : null;
}

function num(value: any): number | null {
  const out = Number(value);
  return Number.isFinite(out) ? out : null;
}

function inferChainTicker(chainId: string | null): string | null {
  if (!chainId) return null;
  if (chainId.includes('litecoin')) return 'LTC';
  if (chainId.includes('bitcoin')) return 'BTC';
  return null;
}

function findFundingAddress(parallelUtxoIndex: AnyObj | null): string | null {
  const outputs = Array.isArray(parallelUtxoIndex?.transactions)
    ? parallelUtxoIndex.transactions.flatMap((item: AnyObj) => Array.isArray(item?.outputs) ? item.outputs : [])
    : [];
  return str(outputs.find((output: AnyObj) => output?.role === 'funding-output')?.address);
}

function findSelectedPathTxid(parallelUtxoIndex: AnyObj | null, selectedPathId: string | null): string | null {
  if (!selectedPathId || !Array.isArray(parallelUtxoIndex?.transactions)) return null;
  const record = parallelUtxoIndex.transactions.find((item: AnyObj) => str(item?.txRole) === selectedPathId);
  return txid(record?.txid);
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function contextHashPayload(context: {
  chainId: string | null;
  templateId: string | null;
  contractId: string | null;
  fundingTxid: string | null;
  fundingVout: number | null;
  selectedPathId: string | null;
  selectedPathTxid: string | null;
  receiptPropertyId?: number;
  settlementRoute: string | null;
}): string {
  return JSON.stringify({
    chainId: context.chainId || '',
    templateId: context.templateId || '',
    contractId: context.contractId || '',
    fundingTxid: context.fundingTxid || '',
    fundingVout: context.fundingVout ?? '',
    selectedPathId: context.selectedPathId || '',
    selectedPathTxid: context.selectedPathTxid || '',
    receiptPropertyId: context.receiptPropertyId || '',
    settlementRoute: context.settlementRoute || '',
  });
}

function artifactSummary(artifact: AnyObj | null): AnyObj | null {
  if (!artifact) return null;
  return {
    kind: str(artifact.kind),
    createdAt: str(artifact.createdAt),
  };
}

function nonReadyStatus(reason: string, query?: BitvmStatusQuery): AnyObj {
  return {
    source: 'bitvmArtifacts',
    featureEnabled: false,
    commitScheme: 'bitvm-dlc-procedural-receipt',
    updatedAt: Date.now(),
    query: query || {},
    procedural: {
      enabled: true,
      ready: false,
      executionContextReady: false,
      contextWarnings: [],
      contextErrors: [reason],
    },
  };
}

export function buildBitvmStatusFromArtifacts(query: BitvmStatusQuery = {}): AnyObj {
  const proceduralSync = readJson(ARTIFACT_FILES.proceduralSync);
  const pipeline = readJson(ARTIFACT_FILES.pipeline);
  const parallelUtxoIndex = readJson(ARTIFACT_FILES.parallelUtxoIndex);
  const challengeBundle = readJson(ARTIFACT_FILES.challengeBundle);
  const draft = readJson(ARTIFACT_FILES.draft);

  if (!proceduralSync) {
    return nonReadyStatus(`Missing ${ARTIFACT_FILES.proceduralSync}`, query);
  }

  const requestedPropertyId = num(query.propertyId);
  const receiptPropertyId = num(proceduralSync.propertyId);
  if (requestedPropertyId && receiptPropertyId && requestedPropertyId !== receiptPropertyId) {
    return nonReadyStatus(`No BitVM procedural context for propertyId ${requestedPropertyId}`, query);
  }

  const errors: string[] = [];
  const warnings: string[] = [];
  const chainId = lower(
    proceduralSync?.parallelUtxoIndex?.chainId ||
    parallelUtxoIndex?.chain?.chainId ||
    draft?.chain?.chainId,
  );
  const chainTicker = inferChainTicker(chainId);
  const templateId = str(proceduralSync.templateId);
  const templateHash = lower(proceduralSync.templateHash);
  const draftTemplateId = str(draft?.template?.templateId);
  const draftTemplateHash = lower(draft?.template?.templateHash);
  const contractId = str(proceduralSync.contractId);
  const fundingTxid = txid(
    proceduralSync.fundingTxid ||
    proceduralSync?.parallelUtxoIndex?.fundingTxid ||
    parallelUtxoIndex?.anchors?.fundingTxid ||
    challengeBundle?.binding?.fundingTxidFinalized,
  );
  const fundingVout = num(
    proceduralSync?.funding?.fundingOutpoint?.vout ??
    proceduralSync?.fundingOutpoint?.vout ??
    parallelUtxoIndex?.anchors?.fundingOutpoint?.vout ??
    challengeBundle?.binding?.fundingOutpoint?.vout,
  );
  const fundedAmountLtc = num(proceduralSync.fundedAmountLtc);
  const selectedPathId = str(
    challengeBundle?.selectedPathId ||
    challengeBundle?.selectedPath?.pathId ||
    pipeline?.options?.selectedPath ||
    proceduralSync?.settlement?.route,
  );
  const selectedPathTxid = txid(challengeBundle?.selectedPath?.txid) || findSelectedPathTxid(parallelUtxoIndex, selectedPathId);
  const settlementRoute = str(proceduralSync?.settlement?.route || selectedPathId);
  const settlementKind = str(proceduralSync?.settlement?.settlementKind);
  const fundingAddress = findFundingAddress(parallelUtxoIndex);
  const operatorAddress = str(proceduralSync.operatorAddress);
  const fundingOutpoint = fundingTxid && fundingVout !== null ? `${fundingTxid}:${fundingVout}` : null;
  const contextId = chainId && fundingOutpoint && selectedPathId ? `${chainId}:${fundingOutpoint}:${selectedPathId}` : null;
  const contextHash = contextId
    ? sha256Hex(contextHashPayload({
        chainId,
        templateId,
        contractId,
        fundingTxid,
        fundingVout,
        selectedPathId,
        selectedPathTxid,
        receiptPropertyId: receiptPropertyId || undefined,
        settlementRoute,
      }))
    : null;

  if (!templateId) errors.push('Missing templateId in procedural sync artifact.');
  if (!contractId) errors.push('Missing contractId in procedural sync artifact.');
  if (!fundingTxid) errors.push('Missing fundingTxid in referee artifacts.');
  if (fundingVout === null) errors.push('Missing fundingVout in referee artifacts.');
  if (!selectedPathId) errors.push('Missing selectedPathId in referee artifacts.');
  if (!selectedPathTxid) errors.push('Missing selectedPathTxid for the selected BitVM path.');
  if (!fundingAddress) errors.push('Missing funding output address in parallel UTXO index.');
  if (!operatorAddress) errors.push('Missing operatorAddress in procedural sync artifact.');
  if (draftTemplateId && templateId && draftTemplateId !== templateId) {
    errors.push(`DLC draft templateId (${draftTemplateId}) does not match procedural sync templateId (${templateId}).`);
  }
  if (draftTemplateHash && templateHash && draftTemplateHash !== templateHash) {
    errors.push(`DLC draft templateHash (${draftTemplateHash}) does not match procedural sync templateHash (${templateHash}).`);
  }

  const settlementValidation = str(
    pipeline?.summary?.settlementValidation?.status ||
    (Array.isArray(pipeline?.steps) ? pipeline.steps.find((step: AnyObj) => step?.id === 'settlementValidation')?.status : null),
  );
  if (settlementValidation && settlementValidation !== 'ok') {
    warnings.push(`Settlement validation is ${settlementValidation}; artifact chain is not fully validated.`);
  }

  const ready = errors.length === 0;
  const procedural = {
    enabled: true,
    ready,
    executionContextReady: ready,
    validationReady: settlementValidation === 'ok',
    replayOnly: true,
    releaseReady: false,
    artifactDir: artifactsDir(),
    chainId,
    chainTicker,
    state: str(proceduralSync.state),
    receiptPropertyId: receiptPropertyId || undefined,
    receiptTicker: chainTicker ? `r${chainTicker}-SAT` : null,
    collateralPropertyId: Number(process.env.BITVM_COLLATERAL_PROPERTY_ID || 1),
    adminAddress: operatorAddress,
    vaultAddress: fundingAddress,
    fundingAddress,
    releaseSpendAddress: operatorAddress,
    holderAddress: str(proceduralSync.holderAddress),
    operatorAddress,
    oracleAddress: str(proceduralSync.oracleAddress),
    residualAddress: str(proceduralSync.residualAddress),
    templateId,
    templateHash,
    contractId,
    mintSettlementState: 'FUNDED',
    redeemSettlementState: 'SETTLED',
    fundingTxid,
    fundingVout,
    fundingOutpoint,
    fundedAmountLtc,
    settlementRoute,
    settlementKind,
    selectedPathId,
    selectedPathTxid,
    executionContextId: contextId,
    executionContextHash: contextHash,
    contextWarnings: warnings,
    contextErrors: errors,
    sourceArtifacts: {
      proceduralSync: artifactSummary(proceduralSync),
      pipeline: artifactSummary(pipeline),
      parallelUtxoIndex: artifactSummary(parallelUtxoIndex),
      challengeBundle: artifactSummary(challengeBundle),
      draft: artifactSummary(draft),
    },
  };

  return {
    source: 'bitvmArtifacts',
    featureEnabled: ready,
    commitScheme: 'bitvm-dlc-procedural-receipt',
    updatedAt: Date.now(),
    query: query || {},
    procedural,
    pipeline: {
      status: str(pipeline?.status),
      mode: str(pipeline?.options?.mode),
      selectedPath: str(pipeline?.options?.selectedPath),
      settlementValidation,
    },
  };
}
