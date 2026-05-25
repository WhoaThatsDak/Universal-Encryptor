<script>
  import { onMount } from "svelte";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const FORMAT_VERSION = "DKENC5";
  const MAX_OUTPUT_CHARS = 2000;
  const FLAG_COMPRESSED = 1;
  const PASSWORD_WARNING_STORAGE_KEY = "universal-encryptor-hide-password-warning";

  let password = "";
  let inputText = "";
  let outputText = "";
  let status = "Loading crypto...";
  let cryptoReady = false;
  let inputCount = 0;
  let outputCount = 0;
  let sodium;
  let showPassword = false;
  let showPasswordWarning = false;
  let skipFuturePasswordWarnings = false;
  let pendingEncrypt = false;
  let allowWeakPasswordOnce = false;

  $: inputCount = inputText.length;
  $: outputCount = outputText.length;

  function argonOps() {
    return sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  }

  function argonMem() {
    return sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  }

  function argonAlg() {
    return sodium.crypto_pwhash_ALG_ARGON2ID13;
  }

  function setStatus(text) {
    status = text || "";
  }

  function bytesToBase64Url(bytes) {
    return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  function base64UrlToBytes(base64url) {
    return sodium.from_base64(
      base64url.trim(),
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
  }

  function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }

    return result;
  }

  async function compressBytes(bytes) {
    if (!("CompressionStream" in window)) {
      return null;
    }

    const stream = new Blob([bytes]).stream().pipeThrough(
      new CompressionStream("deflate")
    );
    const compressedBuffer = await new Response(stream).arrayBuffer();
    return new Uint8Array(compressedBuffer);
  }

  async function decompressBytes(bytes) {
    if (!("DecompressionStream" in window)) {
      throw new Error("This browser cannot decompress this encrypted text.");
    }

    const stream = new Blob([bytes]).stream().pipeThrough(
      new DecompressionStream("deflate")
    );
    const decompressedBuffer = await new Response(stream).arrayBuffer();
    return new Uint8Array(decompressedBuffer);
  }

  async function makeShortestPlaintextBytes(message) {
    const originalBytes = encoder.encode(message);
    const compressedBytes = await compressBytes(originalBytes);

    if (compressedBytes && compressedBytes.length < originalBytes.length) {
      return {
        bytes: compressedBytes,
        flags: FLAG_COMPRESSED,
        compressed: true
      };
    }

    return {
      bytes: originalBytes,
      flags: 0,
      compressed: false
    };
  }

  function checkPasswordStrength(value) {
    if (value.length < 20) {
      return "Use at least 20 characters. A long random passphrase is best.";
    }

    const commonPatterns = [
      "password",
      "123456",
      "qwerty",
      "iloveyou",
      "letmein",
      "admin"
    ];

    const lowered = value.toLowerCase();

    for (const pattern of commonPatterns) {
      if (lowered.includes(pattern)) {
        return "Avoid common words or patterns in your password.";
      }
    }

    return "";
  }

  function shouldShowPasswordWarning() {
    return localStorage.getItem(PASSWORD_WARNING_STORAGE_KEY) !== "true";
  }

  function rememberPasswordWarningPreference() {
    localStorage.setItem(
      PASSWORD_WARNING_STORAGE_KEY,
      skipFuturePasswordWarnings ? "true" : "false"
    );
  }

  function deriveKey(value, salt) {
    return sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      value,
      salt,
      argonOps(),
      argonMem(),
      argonAlg()
    );
  }

  async function ensureCryptoReady() {
    sodium = window.sodium;

    if (!sodium) {
      throw new Error("libsodium was not loaded.");
    }

    await sodium.ready;
  }

  async function encryptMessage() {
    if (!inputText.trim()) {
      window.alert("Enter something to encrypt.");
      return;
    }

    if (!password) {
      window.alert("Enter a password.");
      return;
    }

    const strengthWarning = checkPasswordStrength(password);
    if (strengthWarning && shouldShowPasswordWarning() && !allowWeakPasswordOnce) {
      showPasswordWarning = true;
      pendingEncrypt = true;
      return;
    }

    allowWeakPasswordOnce = false;
    pendingEncrypt = false;

    try {
      setStatus("Compressing and encrypting...");

      const compact = await makeShortestPlaintextBytes(inputText);
      const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
      const nonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
      );
      const key = deriveKey(password, salt);

      const versionBytes = encoder.encode(FORMAT_VERSION);
      const flagsByte = new Uint8Array([compact.flags]);
      const aad = concatBytes(versionBytes, flagsByte);

      const encryptedBytes =
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          compact.bytes,
          aad,
          null,
          nonce,
          key
        );

      const finalBytes = concatBytes(
        versionBytes,
        flagsByte,
        salt,
        nonce,
        encryptedBytes
      );

      const finalText = bytesToBase64Url(finalBytes);
      outputText = finalText;

      const compressionText = compact.compressed
        ? "Compressed before encryption."
        : "Compression skipped because it would not shorten this message.";

      if (finalText.length > MAX_OUTPUT_CHARS) {
        setStatus(
          `Encrypted. ${compressionText}\nWon't send in one Discord message.\nOutput is ${finalText.length}/${MAX_OUTPUT_CHARS} characters.`
        );
      } else {
        setStatus(
          `Encrypted. ${compressionText} Output is ${finalText.length}/${MAX_OUTPUT_CHARS} characters.`
        );
      }
    } catch (error) {
      console.error(error);
      setStatus("");
      window.alert("Encryption failed.");
    }
  }

  async function decryptMessage() {
    if (!inputText.trim()) {
      window.alert("Paste encrypted text first.");
      return;
    }

    if (!password) {
      window.alert("Enter the password.");
      return;
    }

    try {
      setStatus("Decrypting...");

      const finalBytes = base64UrlToBytes(inputText);
      const versionLength = FORMAT_VERSION.length;
      const flagsLength = 1;
      const saltLength = sodium.crypto_pwhash_SALTBYTES;
      const nonceLength = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

      const versionBytes = finalBytes.slice(0, versionLength);
      const version = decoder.decode(versionBytes);

      if (version !== FORMAT_VERSION) {
        throw new Error("Unsupported format.");
      }

      const flagsStart = versionLength;
      const flagsEnd = flagsStart + flagsLength;
      const flagsByte = finalBytes.slice(flagsStart, flagsEnd);
      const flags = flagsByte[0];

      const saltStart = flagsEnd;
      const saltEnd = saltStart + saltLength;
      const nonceStart = saltEnd;
      const nonceEnd = nonceStart + nonceLength;
      const encryptedStart = nonceEnd;

      const salt = finalBytes.slice(saltStart, saltEnd);
      const nonce = finalBytes.slice(nonceStart, nonceEnd);
      const encryptedBytes = finalBytes.slice(encryptedStart);

      const key = deriveKey(password, salt);
      const aad = concatBytes(versionBytes, flagsByte);

      let decryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        encryptedBytes,
        aad,
        nonce,
        key
      );

      if (flags & FLAG_COMPRESSED) {
        decryptedBytes = await decompressBytes(decryptedBytes);
      }

      outputText = decoder.decode(decryptedBytes);
      setStatus("Decrypted.");
    } catch (error) {
      console.error(error);
      setStatus("");
      window.alert(
        "Could not decrypt. Wrong password, corrupted text, or unsupported format."
      );
    }
  }

  async function copyOutput() {
    if (!outputText.trim()) {
      window.alert("There is nothing to copy.");
      return;
    }

    await navigator.clipboard.writeText(outputText);
    setStatus("Copied output to clipboard.");
  }

  function clearBoxes() {
    inputText = "";
    outputText = "";
    setStatus("");
  }

  function continueAfterPasswordWarning() {
    rememberPasswordWarningPreference();
    showPasswordWarning = false;
    allowWeakPasswordOnce = true;

    if (pendingEncrypt) {
      encryptMessage();
    }
  }

  function cancelPasswordWarning() {
    rememberPasswordWarningPreference();
    pendingEncrypt = false;
    showPasswordWarning = false;
  }

  onMount(async () => {
    try {
      await ensureCryptoReady();
      cryptoReady = true;
      setStatus("Crypto loaded.");
    } catch (error) {
      console.error(error);
      setStatus("Crypto failed to load.");
    }
  });
</script>

<svelte:head>
  <meta
    name="description"
    content="Compact browser encryptor using Argon2id and XChaCha20-Poly1305."
  />
</svelte:head>

<div class="shell">
  <section class="app">
    <div class="hero">
      <h1>Universal Encryptor</h1>
    </div>

    <label for="password">Password</label>
    <input
      id="password"
      type={showPassword ? "text" : "password"}
      bind:value={password}
      placeholder="Use a long random passphrase"
      autocomplete="off"
      spellcheck="false"
    />
    <label class="toggle">
      <input type="checkbox" bind:checked={showPassword} />
      <span>Show password</span>
    </label>

    <label for="input">Input</label>
    <textarea
      id="input"
      bind:value={inputText}
      placeholder="Type text to encrypt or paste encrypted text to decrypt"
      spellcheck="false"
    ></textarea>
    <div class="small">Input: {inputCount} characters</div>

    <div class="buttons">
      <button class="encrypt" on:click={encryptMessage} disabled={!cryptoReady}>
        Encrypt
      </button>
      <button class="decrypt" on:click={decryptMessage} disabled={!cryptoReady}>
        Decrypt
      </button>
      <button class="copy" on:click={copyOutput}>Copy</button>
      <button class="clear" on:click={clearBoxes}>Clear</button>
    </div>

    <div class="status">{status}</div>

    <label for="output">Output</label>
    <textarea
      id="output"
      bind:value={outputText}
      readonly
      placeholder="Result appears here"
      spellcheck="false"
    ></textarea>
    <div class="small">Output: {outputCount} / {MAX_OUTPUT_CHARS} characters</div>
  </section>
</div>

{#if showPasswordWarning}
  <div class="overlay">
    <section class="dialog">
      <h2>Weak Password Warning</h2>
      <p>
        This password looks weak or predictable. You can still continue, but a
        longer random passphrase is safer.
      </p>
      <label class="toggle">
        <input type="checkbox" bind:checked={skipFuturePasswordWarnings} />
        <span>Do not show this warning again on this device</span>
      </label>
      <div class="dialog-actions">
        <button class="clear" on:click={cancelPasswordWarning}>Cancel</button>
        <button class="encrypt" on:click={continueAfterPasswordWarning}>
          Continue
        </button>
      </div>
    </section>
  </div>
{/if}

<style>
  .shell {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 24px;
  }

  .app {
    width: min(100%, 840px);
    padding: 28px;
    border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 28px;
    background: rgba(15, 23, 42, 0.86);
    box-shadow: 0 28px 80px rgba(2, 6, 23, 0.45);
    backdrop-filter: blur(14px);
  }

  .hero {
    margin-bottom: 18px;
  }

  h1 {
    margin: 0;
    font-size: clamp(2rem, 5vw, 3rem);
    line-height: 1;
  }

  label {
    display: block;
    margin: 16px 0 8px;
    font-weight: 700;
    color: #e2e8f0;
  }

  textarea,
  input {
    width: 100%;
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 14px 16px;
    background: rgba(15, 23, 42, 0.9);
    color: #f8fafc;
    outline: none;
    transition:
      border-color 160ms ease,
      transform 160ms ease,
      box-shadow 160ms ease;
  }

  textarea:focus,
  input:focus {
    border-color: #38bdf8;
    box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.15);
  }

  textarea {
    min-height: 150px;
    resize: vertical;
  }

  .buttons {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
    margin-top: 18px;
  }

  button {
    border: 0;
    border-radius: 16px;
    padding: 13px 14px;
    color: #eff6ff;
    font-weight: 700;
    cursor: pointer;
    transition:
      transform 160ms ease,
      opacity 160ms ease,
      filter 160ms ease;
  }

  button:hover:enabled {
    transform: translateY(-1px);
    filter: brightness(1.05);
  }

  button:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }

  .encrypt {
    background: linear-gradient(135deg, #2563eb, #0ea5e9);
  }

  .decrypt {
    background: linear-gradient(135deg, #16a34a, #22c55e);
  }

  .copy {
    background: linear-gradient(135deg, #c2410c, #f97316);
  }

  .clear {
    background: linear-gradient(135deg, #dc2626, #f43f5e);
  }

  .status {
    min-height: 44px;
    margin-top: 14px;
    padding: 12px 14px;
    border-radius: 14px;
    background: rgba(30, 41, 59, 0.75);
    color: #fde68a;
    white-space: pre-wrap;
    line-height: 1.45;
  }

  .small {
    margin-top: 8px;
    color: #94a3b8;
    font-size: 0.92rem;
    text-align: right;
  }

  .toggle {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 10px;
    color: #cbd5e1;
    font-weight: 500;
  }

  .toggle input {
    width: auto;
    margin: 0;
  }

  .overlay {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    padding: 24px;
    background: rgba(2, 6, 23, 0.72);
  }

  .dialog {
    width: min(100%, 460px);
    padding: 22px;
    border: 1px solid rgba(148, 163, 184, 0.22);
    border-radius: 24px;
    background: #0f172a;
    box-shadow: 0 24px 70px rgba(2, 6, 23, 0.55);
  }

  .dialog h2 {
    margin: 0 0 10px;
    font-size: 1.3rem;
  }

  .dialog p {
    margin: 0;
    color: #cbd5e1;
    line-height: 1.5;
  }

  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    margin-top: 18px;
  }

  @media (max-width: 720px) {
    .app {
      padding: 20px;
      border-radius: 22px;
    }

    .buttons {
      grid-template-columns: 1fr 1fr;
    }
  }
</style>
