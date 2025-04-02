const { stderr } = require('process');

module.exports = async (core, exec, vault, secrets) => {
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

    const results = {};

    await exec.exec('az', [
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
    ], {
      silent: true,
      listeners: {
        stdout: (data) => {
          secretValue += data.toString();
        }
      },
    });

    secretValue = secretValue.trim();

    // Mask the raw secret value in logs
    core.setSecret(secretValue);

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

      core.setSecret(secretValue); // Mask the decoded value as well
    }

    const fs = require('fs');

    if (output.startsWith('$env:')) {
      // Environment variable
      const envVarName = output.replace('$env:', '').trim();
      fs.appendFileSync(process.env.GITHUB_ENV, `${envVarName}=${secretValue}\n`);
      core.info(`Secret set as environment variable: ${envVarName}`);
    } else if (output.startsWith('$output:')) {
      // GitHub Actions output variable
      const outputName = output.replace('$output:', '').trim();
      results[outputName] = secretValue.trim();
      core.info(`Secret set as output variable: ${outputName}`);
    } else {
      // File output
      const filePath = output.trim();
      const fileDir = filePath.substring(0, filePath.lastIndexOf('/'));
      if (!fs.existsSync(fileDir)) {
        fs.mkdirSync(fileDir, { recursive: true });
      }
      fs.writeFileSync(filePath, secretValue.trim());
      core.info(`Secret written to file: ${filePath}`);
    }

    core.setOutput('secrets', results);
  }
}
