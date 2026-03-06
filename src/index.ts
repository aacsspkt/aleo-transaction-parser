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
        // console.log("Output JSON:", output);
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
        // const senderCiphertextPresent = !!senderCiphertextStr;
        // console.log(
        //     `Sender ciphertext present: ${senderCiphertextPresent}, value: ${senderCiphertextStr}`,
        // );
        let sender: string | null = null;
        if (senderCiphertextStr) {
            try {
                sender = EncryptionToolkit.decryptSenderWithRvk(
                    recordViewKey,
                    Field.fromString(senderCiphertextStr),
                ).to_string();
                // console.log(`Decrypted sender: ${JSON.stringify(sender)}`);
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
    // console.log("Parsing transfer_public transition:", transition);
    // transfer_public inputs: [sender_record_or_addr, recipient_addr, amount]
    // Input[1] = recipient address (public), Input[2] = amount (public)

    //  outputs: [
    //     {
    //       id: '2221493080266397082577948705279676078341888870797048480034912571028007188428field',
    //       type: 'future',
    //       value: '{\n' +
    //         '  program_id: credits.aleo,\n' +
    //         '  function_name: transfer_public,\n' +
    //         '  arguments: [\n' +
    //         '    aleo1sagjjc3la7cxtlvczs3mzngg9sfnz30x27y8n40kmdqysvz7yqysf4jl2k,\n' +
    //         '    aleo124nwdusaydj0qrwuul74wg9283j7j88sh53uxqvy88fjxh2wpy9suwyad5,\n' +
    //         '    100000u64\n' +
    //         '  ]\n' +
    //         '}'
    //     }
    //   ]
    const inputs = transition.inputs;
    // console.log("Inputs for transfer_public:", inputs);
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

    // self.caller is passed as the first future argument in transfer_public
    const outputs = transition.outputs || [];
    // console.log("Outputs for transfer_public:", outputs);

    if (outputs.length === 0) {
        return null;
    }

    const futureOutput = outputs.find((o) => o.type.toLowerCase() === "future");

    if (!futureOutput) {
        return null;
    }

    let sender: string | null = null;
    try {
        // console.log("Parsed future output value:", futureOutput.value);
        // Use a regex to retrieve first argument (sender address) of arguments from the future output value
        // if the program_id is credits.aleo, otherwise retrieve the third argument for stable coin transfer
        const programIdMatch = futureOutput.value.match(
            /program_id:\s*([a-z0-9._]+)/,
        );

        if (!programIdMatch) {
            console.warn("Could not parse program_id from future output value");
            return null;
        }
        const programId = programIdMatch[1] ?? "";
        // console.log("Program ID from future output:", programId);
        if (programId === "credits.aleo") {
            // Format of future output value for credit transfer:
            // '{\n' +
            // '  program_id: credits.aleo,\n' +
            // '  function_name: transfer_public,\n' +
            // '  arguments: [\n' +
            // '    aleo1sagjjc3la7cxtlvczs3mzngg9sfnz30x27y8n40kmdqysvz7yqysf4jl2k,\n' +
            // '    aleo124nwdusaydj0qrwuul74wg9283j7j88sh53uxqvy88fjxh2wpy9suwyad5,\n' +
            // '    100000u64\n' +
            // '  ]\n' +
            // '}'
            // Here the sender address is in first argument
            const firstArgMatch = futureOutput.value.match(
                /arguments:\s*\[\s*([^,\s]+),/,
            );
            if (firstArgMatch) {
                sender = firstArgMatch[1] ?? null;
            }
        } else {
            // Format of future output value for stable coin transfer in transfer_public
            // '{\n' +
            // '  program_id: usad_stablecoin.aleo,\n' +
            // '  function_name: transfer_public,\n' +
            // '  arguments: [\n' +
            // '    aleo124nwdusaydj0qrwuul74wg9283j7j88sh53uxqvy88fjxh2wpy9suwyad5,\n' +
            // '    100000u128,\n' +
            // '    aleo1y73q70efzq3uqx05wygyl3a33g6veva6lavwwwex39lx46glc59sa2uc3f\n' +
            // '  ]\n' +
            // '}'
            // Here the sender address is in the third argument
            // this regex should match the third argument in the arguments array handling \n
            const thirdArgMatch = futureOutput.value.match(
                /arguments:\s*\[\s*(?:[^\],]+,\s*){2}(aleo1[a-z0-9]+)/,
            );
            if (thirdArgMatch) {
                // console.log("Third argument match for sender:", thirdArgMatch);
                sender = thirdArgMatch[1] ?? null;
            }
        }
    } catch (error) {
        console.error("Failed to parse future output value as JSON:", error);
    }

    return {
        transactionId: txId,
        transitionId: transition.id,
        programId: transition.program,
        functionName: transition.function,
        recipient: recipientInput.value,
        rawAmount,
        amount,
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
    const recipientAddress = recipient.address().to_string();

    // 2. Fetch transaction from network
    const rpcUrl = "https://api.provable.com/v2";

    const networkClient = new AleoNetworkClient(rpcUrl);
    const tx = await networkClient.getTransaction(txId);

    // console.log("Fetched transaction:", tx);

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
    const recipientAddress = account.address().to_string();

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

export async function parseAleoTransfers(txIds: string[], recipient: Account) {
    await Promise.all(
        txIds.map(async (txId) => {
            const result = await decryptAleoTransfer(txId, recipient);

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
            console.log("Amount         :", result.rawAmount.toString());
            console.log("Amount (human) :", result.amount);
            console.log("\n");
        }),
    );
}

async function main() {
    const RECIPIENT_PRIVATE_KEY = process.env.RECIPIENT_PRIVATE_KEY;
    if (!RECIPIENT_PRIVATE_KEY) {
        throw new Error("Please set RECIPIENT_PRIVATE_KEY in your .env file");
    }

    const TX_IDS = [
        "at1xr52jse7t5zqg6fmzkclh256pndlmywyvcdjj7q00sarxtz92gpqt9w5f6",
        "at1h3l9cqaw50we5rzlrgq2cl24x8q3szd5d299huapsl8uhh4kwq9swpznj8",
    ]; // testnet
    // const TX_IDS = [
    //     "at1kgecnhkzcp2ft5nczwdrghzxrw28s8zqudl90jas8umnywy60cpqf0e536",
    //     "at1qh09c53u6y5u9pap67c3k8daa6v5jh6tpx20hraxn5vvmlq4xgrsyjq44q",
    //     "at1v3568y6eev9m0hu798acrm445jqzc5h5jedw4lhly69rtrksp5qsayj8py",
    // ]; // mainnet
    // --- Option A: fetch from network ---
    console.log("Fetching and decrypting transaction...\n");
    const recipient = new Account({ privateKey: RECIPIENT_PRIVATE_KEY });
    await parseAleoTransfers(TX_IDS, recipient);
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
