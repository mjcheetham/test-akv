const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');

const escapeData = (s) => {
  return s
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A')
}

const writeCommand = (file, name, value) => {
  // Unique delimiter to avoid conflicts with actual values
  let delim;
  for (let count = 0; ; count++) {
    delim = `XXXXXX${count}`;
    if (!name.includes(delim) && !value.includes(delim)) {
      break;
    }
  }

  fs.appendFileSync(file, `${name}<<${delim}${os.EOL}${value}${os.EOL}${delim}${os.EOL}`);
}

const setSecret = (value) => {
  process.stdout.write(`::add-mask::${escapeData(value)}${os.EOL}`);
}

const setOutput = (name, value) => {
  writeCommand(process.env.GITHUB_OUTPUT, name, value);
}

const exportVariable = (name, value) => {
  writeCommand(process.env.GITHUB_ENV, name, value);
}

const logInfo = (message) => {
  process.stdout.write(`${message}${os.EOL}`);
}

const setFailed = (error) => {
  process.stdout.write(`::error::${escapeData(error.message)}${os.EOL}`);
  process.exitCode = 1;
}

(async () => {
  const vault = process.env.INPUT_VAULT;
  const secrets = process.env.INPUT_SECRETS;

  try {
    // Parse and normalize secret mappings
    const secretMappings = secrets
      .split(/[\n,]+/)
      .map((entry) => entry.trim())
      .filter((entry) => entry)
      .map((entry) => {
        const [input, encoding, output] = entry.split(/(\S+)?>/).map((part) => part?.trim());
        return { input, encoding, output: output || `\$output:${input}` }; // Default output to $output:input if not specified
      });

    if (secretMappings.length === 0) {
      throw new Error('No secrets provided.');
    }

    // Fetch secrets from Azure Key Vault
    for (const { input: secretName, encoding, output } of secretMappings) {
      let secretValue = '';

      const az = spawnSync('az',
        [
          'keyvault',
          'secret',
          'show',
          '--vault-name',
          vault,
          '--name',
          secretName,
          '--query',
          'value',
          '--output',
          'tsv'
        ],
        {
          stdio: ['ignore', 'pipe', 'inherit'],
          shell: true // az is a batch script on Windows
        }
      );

      if (az.error) throw new Error(az.error, { cause: az.error });
      if (az.status !== 0) throw new Error(`az failed with status ${az.status}`);

      secretValue = az.stdout.toString('utf-8').trim();

      // Mask the raw secret value in logs
      setSecret(secretValue);

      // Handle encoded values if specified
      // Sadly we cannot use the `--encoding` parameter of the `az keyvault
      // secret (show|download)` command as the former does not support it, and
      // the latter must be used with `--file` (we could use /dev/stdout on UNIX
      // but not on Windows).
      if (encoding) {
        switch (encoding.toLowerCase()) {
          case 'base64':
            secretValue = Buffer.from(secretValue, 'base64').toString();
            break;
          default:
            // No decoding needed
        }

        setSecret(secretValue); // Mask the decoded value as well
      }

      if (output.startsWith('$env:')) {
        // Environment variable
        const envVarName = output.replace('$env:', '').trim();
        exportVariable(envVarName, secretValue);
        logInfo(`Secret set as environment variable: ${envVarName}`);
      } else if (output.startsWith('$output:')) {
        // GitHub Actions output variable
        const outputName = output.replace('$output:', '').trim();
        setOutput(outputName, secretValue);
        logInfo(`Secret set as output variable: ${outputName}`);
      } else {
        // File output
        const filePath = output.trim();
        const fileDir = filePath.substring(0, filePath.lastIndexOf('/'));
        if (!fs.existsSync(fileDir)) {
          fs.mkdirSync(fileDir, { recursive: true });
        }
        fs.writeFileSync(filePath, secretValue);
        logInfo(`Secret written to file: ${filePath}`);
      }
    }
  } catch (error) {
    setFailed(error);
  }
})();
