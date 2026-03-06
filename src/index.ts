import process from "node:process";
import {
    Account,
    AleoNetworkClient,
    EncryptionToolkit,
    Field,
    RecordCiphertext,
    type RecordPlaintext,
    type TransactionJSON,
    type TransitionJSON,
    type ViewKey,
} from "@provablehq/sdk/testnet.js";
import BigNumber from "bignumber.js";
import dotenv from "dotenv";

dotenv.config();

export interface DecryptedTransferResult {
    /** Transaction ID */
    transactionId: string;
    /** Transition ID (au1...) */
    transitionId: string;
    /** e.g. "credits.aleo" or "token.aleo" */
    programId: string;
    /** "transfer_private" or "transfer_public" */
    functionName: string;
    /** Recipient Aleo address */
    recipient: string;
    /** Raw amount as bigint (microcredits for native, raw units for tokens) */
    rawAmount: bigint;
    /** Human-readable amount (divided by 1_000_000 for credits) */
    amount: number;
    /** The unit field name found in the record, e.g. "microcredits" or "amount" */
    amountField: string;
    /** Whether this was a private or public transfer */
    transferType: "private" | "public";
    /**
     * Sender Aleo address, or null if not recoverable.
     * - For transfer_private: decrypted from output's sender_ciphertext using
     *   EncryptionToolkit.decryptSenderWithRvk(recordViewKey, sender_ciphertext).
     * - For transfer_public: extracted from transition.finalize[0] (self.caller).
     */
    sender: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse the owner address from a decrypted record plaintext string.
 * Record format: "{ owner: aleo1..., microcredits: 1000000u64.private, ... }"
 */
function parseOwner(plaintext: string): string | null {
    const match = plaintext.match(/owner:\s*(aleo1[a-z0-9]+)/);
    return match ? (match[1] ? match[1] : null) : null;
}

/**
 * Parse the amount from a decrypted record plaintext string.
 * Handles both "microcredits: 1000000u64" and "amount: 500000u128" etc.
 * Returns { field, raw } where field is the key name and raw is bigint.
 */
function parseAmount(plaintext: string): { field: string; raw: bigint } | null {
    // Matches: microcredits: 1000000u64  OR  amount: 500000u128
    const match = plaintext.match(
        /(microcredits|amount|balance)\s*:\s*(\d+)u\d+/,
    );
    if (!match) return null;
    return { field: match[1]!, raw: BigInt(match[2]!) };
}

/**
 * Convert microcredits (or raw token units) to a human-readable number.
 * For credits.aleo: 1 credit = 1_000_000 microcredits
 * For other tokens you may need a different divisor — adjust as needed.
 */
function toHuman(raw: bigint, programId: string): number {
    const divisor =
        programId === "credits.aleo" ||
            programId === "usad_stablecoin.aleo" ||
            programId === "usdcx_stablecoin.aleo"
            ? 1_000_000
            : 1_000_000; // better would be to get the token decimals from the program, but we'll assume 6 for this example
    return Number(BigNumber(raw).div(divisor).toFixed());
}

// ---------------------------------------------------------------------------
// Core: decrypt a transfer_private transition
// ---------------------------------------------------------------------------

function decryptPrivateTransfer(
    transition: TransitionJSON,
    viewKey: ViewKey,
    txId: string,
): DecryptedTransferResult | null {
    if (!transition.outputs) {
        return null;
    }

    const recordOutputs = transition.outputs.filter((o) => o.type === "record");
    for (const output of recordOutputs) {
        console.log("Output JSON:", output);
        let ciphertext: RecordCiphertext;
        try {
            ciphertext = RecordCiphertext.fromString(output.value);
        } catch {
            continue; // not a valid record ciphertext, skip
        }

        // isOwner() checks: shared_secret = view_key * tpk, then derives record owner
        let owned: boolean;
        try {
            owned = ciphertext.isOwner(viewKey);
        } catch {
            continue;
        }

        if (!owned) continue;

        // Derive a per-record view key — reused for both decryption and sender recovery
        const recordViewKey = EncryptionToolkit.generateRecordViewKey(
            viewKey,
            ciphertext,
        );

        let plaintext: RecordPlaintext;
        try {
            plaintext = EncryptionToolkit.decryptRecordWithRVk(
                recordViewKey,
                ciphertext,
            );
        } catch (e) {
            throw new Error(`Failed to decrypt record: ${e}`);
        }

        const raw = plaintext.toString();
        const recipient = parseOwner(raw);
        const amountInfo = parseAmount(raw);

        if (!recipient)
            throw new Error(`Could not parse owner from record: ${raw}`);
        if (!amountInfo)
            throw new Error(`Could not parse amount from record: ${raw}`);

        const amount = toHuman(amountInfo.raw, transition.program);

        // Decrypt the sender address using the record view key.
        // sender_ciphertext is present in the API response alongside each record output
        // but is not yet captured in the OutputJSON TypeScript type.
        const senderCiphertextStr = (
            output as unknown as { sender_ciphertext?: string }
        ).sender_ciphertext;
        const senderCiphertextPresent = !!senderCiphertextStr;
        console.log(
            `Sender ciphertext present: ${senderCiphertextPresent}, value: ${senderCiphertextStr}`,
        );
        let sender: string | null = null;
        if (senderCiphertextStr) {
            try {
                sender = EncryptionToolkit.decryptSenderWithRvk(
                    recordViewKey,
                    Field.fromString(senderCiphertextStr),
                ).to_string();
                console.log(`Decrypted sender: ${JSON.stringify(sender)}`);
            } catch {
                // sender_ciphertext present but failed to decrypt — leave as null
            }
        }

        return {
            transactionId: txId,
            transitionId: transition.id,
            programId: transition.program,
            functionName: transition.function,
            recipient,
            rawAmount: amountInfo.raw,
            amount,
            amountField: amountInfo.field,
            transferType: "private",
            sender,
        };
    }

    return null; // no owned record found in this transition
}

// ---------------------------------------------------------------------------
// Core: parse a transfer_public transition (all values are on-chain plaintext)
// ---------------------------------------------------------------------------

function parsePublicTransfer(
    transition: TransitionJSON,
    recipientAddress: string,
    txId: string,
): DecryptedTransferResult | null {
    console.log("Parsing transfer_public transition:", transition);
    // transfer_public inputs: [sender_record_or_addr, recipient_addr, amount]
    // Input[1] = recipient address (public), Input[2] = amount (public)
    const inputs = transition.inputs;

    if (!inputs) {
        return null;
    }

    // Find the "public" type inputs — they hold address and amount
    const publicInputs = inputs.filter((i) => i.type === "public");

    if (publicInputs.length < 2) return null;

    // For credits.aleo/transfer_public:
    //   inputs[0]: sender credits record (type=record) — may be omitted if public-to-public
    //   inputs[1]: recipient address  (type=public)
    //   inputs[2]: amount in microcredits (type=public)

    // Find recipient input (contains "aleo1")
    const recipientInput = publicInputs.find((i) => i.value?.startsWith("aleo1"));
    // Find amount input (contains "u64" or "u128")
    const amountInput = publicInputs.find((i) => i.value?.match(/^\d+u\d+$/));

    if (!recipientInput?.value || !amountInput?.value) return null;

    // Check this transfer is actually TO our recipient
    if (recipientInput.value !== recipientAddress) return null;

    const amountMatch = amountInput.value.match(/^(\d+)u\d+$/);
    if (!amountMatch) return null;

    const rawAmount = BigInt(amountMatch[1]!);
    const amount = toHuman(rawAmount, transition.program);

    // self.caller is passed as the first finalize argument in transfer_public
    const finalize = (transition as unknown as Record<string, unknown>)
        .finalize as string[] | undefined;
    const sender = finalize?.[0]?.startsWith("aleo1")
        ? (finalize[0] ?? null)
        : null;

    return {
        transactionId: txId,
        transitionId: transition.id,
        programId: transition.program,
        functionName: transition.function,
        recipient: recipientInput.value,
        rawAmount,
        amount,
        amountField: "microcredits",
        transferType: "public",
        sender,
    };
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

/**
 * Decrypts an Aleo transfer transaction and extracts transfer details.
 *
 * @param txId          - Transaction ID (at1...)
 * @param privateKeyStr - Recipient's private key (APrivateKey1...)
 * @param network       - Optional: "mainnet" | "testnet" (default: "mainnet")
 * @returns             - Decoded transfer info, or null if not directed to this key
 */
export async function decryptAleoTransfer(
    txId: string,
    recipient: Account,
): Promise<DecryptedTransferResult | null> {
    // 1. Derive account + view key from private key
    const viewKey = recipient.viewKey();
    const recipientAddress = recipient.address().toString();

    // 2. Fetch transaction from network
    const rpcUrl = "https://api.provable.com/v2";

    const networkClient = new AleoNetworkClient(rpcUrl);
    const tx = await networkClient.getTransaction(txId);

    if (!tx?.execution?.transitions?.length) {
        throw new Error(`Transaction ${txId} has no execution transitions`);
    }

    // 3. Find the transfer transition (skip fee_public etc.)
    const transferTransitions = tx.execution.transitions.filter(
        (t) =>
            t.function === "transfer_private" || t.function === "transfer_public",
    );

    if (!transferTransitions.length) {
        throw new Error(
            `No transfer_private or transfer_public transition found in tx ${txId}. ` +
            `Found: ${tx.execution.transitions.map((t) => t.function).join(", ")}`,
        );
    }

    // 4. Try each qualifying transition
    for (const transition of transferTransitions) {
        if (transition.function === "transfer_private") {
            const result = decryptPrivateTransfer(transition, viewKey, txId);
            if (result) return result;
        } else if (transition.function === "transfer_public") {
            const result = parsePublicTransfer(transition, recipientAddress, txId);
            if (result) return result;
        }
    }

    // No record owned by this key
    return null;
}

// ---------------------------------------------------------------------------
// Alternative: pass the raw transaction object directly (no network call)
// ---------------------------------------------------------------------------

/**
 * Same as decryptAleoTransfer but accepts an already-fetched transaction object.
 * Useful when you already have the tx from a webhook or your own indexer.
 */
export function decryptAleoTransferFromTx(
    tx: TransactionJSON,
    privateKeyStr: string,
): DecryptedTransferResult | null {
    const account = new Account({ privateKey: privateKeyStr });
    const viewKey = account.viewKey();
    const recipientAddress = account.address().toString();

    if (!tx.execution) {
        return null;
    }

    const transferTransitions = tx.execution.transitions.filter(
        (t) =>
            t.function === "transfer_private" || t.function === "transfer_public",
    );

    for (const transition of transferTransitions) {
        if (transition.function === "transfer_private") {
            const result = decryptPrivateTransfer(transition, viewKey, tx.id);
            if (result) return result;
        } else if (transition.function === "transfer_public") {
            const result = parsePublicTransfer(transition, recipientAddress, tx.id);
            if (result) return result;
        }
    }

    return null;
}

async function main() {
    const RECIPIENT_PRIVATE_KEY = process.env.RECIPIENT_PRIVATE_KEY;
    if (!RECIPIENT_PRIVATE_KEY) {
        throw new Error("Please set RECIPIENT_PRIVATE_KEY in your .env file");
    }

    const TX_ID = "at1xr52jse7t5zqg6fmzkclh256pndlmywyvcdjj7q00sarxtz92gpqt9w5f6"; // testnet
    // const TX_ID = "at1qh09c53u6y5u9pap67c3k8daa6v5jh6tpx20hraxn5vvmlq4xgrsyjq44q"; // mainnet

    // --- Option A: fetch from network ---
    console.log("Fetching and decrypting transaction...\n");
    const recipient = new Account({ privateKey: RECIPIENT_PRIVATE_KEY });
    const result = await decryptAleoTransfer(TX_ID, recipient);

    if (!result) {
        console.log(
            "This transaction was not directed to the provided private key.",
        );
        return;
    }

    console.log("=== Transfer Details ===");
    console.log("Transaction ID :", result.transactionId);
    console.log("Transition ID  :", result.transitionId);
    console.log("Program ID     :", result.programId);
    console.log("Function       :", result.functionName);
    console.log("Transfer Type  :", result.transferType);
    console.log("Sender         :", result.sender ?? "(not available)");
    console.log("Recipient      :", result.recipient);
    console.log(`Amount (${result.amountField}):`, result.rawAmount.toString());
    console.log("Amount (human) :", result.amount);
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
