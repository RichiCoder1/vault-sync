import { Application, Context } from "probot";
import { Ok, Err } from '@usefultools/monads';
import got from 'got';
import { JSONPath } from 'jsonpath-plus';
import sodium from 'tweetsodium';
import { getConfig, configFile, VaultSyncConfig } from "./config";
import { getAndVerifyGlobals, VaultGlobalSettings } from "./vaultSettings";
export = (app: Application) => {
	const vaultConfig = getAndVerifyGlobals(app);
	if (!vaultConfig) {
		process.exit(1);
	}

	app.on("push", async context => {
		const defaultBranch = app.cache.wrap(
			`${context.payload.repository.full_name}+default_branch`,
			async callback => {
				try {
					const currentRepo = await context.github.repos.get(context.repo());
					callback(null, currentRepo.data.default_branch);
				} catch (e) {
					callback(e, null);
				}
			},
			{ ttl: 30 * 60 }
		);
	
		if (context.payload.ref !== `refs/heads/${defaultBranch}`) {
			context.log.debug("Non-default branch push. Skipping.", context.repo());
			return;
		}

		await handleSyncEvent(app, context, vaultConfig);
	});
};

const handleSyncEvent = async (app: Application, context: Context, vaultConfig: VaultGlobalSettings) => {
	app.log.info(`Syncing ${context.repo().repo}...`);
	const config = getConfig(context);
	if (!config) {
		context.log.debug(
			`No configuration set in .github/${configFile}. Skipping.`,
			context.repo()
		);
		return;
	}

	try {
		// It's a push to the default branch and we have a config, initiate secret sync
		await syncSecrets({
			config,
			vaultConfig,
			context,
			app
		});
	} catch (e) {
		context.log.fatal('Failed to sync sync secrets:', e);
	}
}

type AppContext = {
	config: VaultSyncConfig;
	vaultConfig: VaultGlobalSettings;
	context: Context;
	app: Application;
};

const syncSecrets = async (context: AppContext) => {
	const { context: { github, repo }, app: { log } } = context;

	let vaultToken: string;
	if ('roleId' in context.vaultConfig) {
		const result = await getAppRoleToken(context);
		if (result.is_ok()) {
			context.app.log.error(...result.unwrap_err());
			return;
		}
		vaultToken = result.unwrap();
	} else {
		vaultToken = context.vaultConfig.token;
	}

	const secretsResponse = await github.actions.listSecretsForRepo(repo());
	if (secretsResponse.status < 200 || secretsResponse.status >= 300) {
		log.error('Unable to list secrets for repo. Make sure the apps permissions are correctly set.', repo(), secretsResponse);
		return;
	}

	const existingSecrets = secretsResponse.data.secrets;
	const configSecrets = new Map(Object.entries(context.config.secrets));

	const uncontrolledSecrets = existingSecrets.map(s => s.name).filter(s => !configSecrets.has(s));

	log.info(`There are ${uncontrolledSecrets.length} uncontrolled secrets: ${uncontrolledSecrets.join(', ')}`);

	const keyResponse = await github.actions.getPublicKey(repo());
	if (keyResponse.status < 200 || keyResponse.status >= 300) {
		log.error('Unable to retrieve public key for repo. Make sure the apps permissions are correctly set.', repo(), keyResponse);
		return;
	}
	
	const { key, key_id } = keyResponse.data;

	let errors = 0;
	for (const [secretName, secretConfig] of configSecrets) {
		let value: string;
		try {
			const secretResponse = await readSecret(secretConfig.path, vaultToken, context);
			
			if (!secretConfig.selector.includes('.')) {
				value = secretResponse['data'][secretConfig.selector];
			} else {
				value = JSONPath({ path: secretConfig.selector, json: secretResponse, preventEval: true });
			}			
		} catch (e) {
			log.error(`Failed to read secret ${secretName}.`);
			errors++;
			if (errors >= 3) {
				log.fatal('To many errors. Aborting...');
				return;
			}
			continue;
		}

		try {
			// Convert the message and key to Uint8Array's (Buffer implements that interface)
			const messageBytes = Buffer.from(value);
			const keyBytes = Buffer.from(key, 'base64');
			
			// Encrypt using LibSodium.
			const encryptedBytes = sodium.seal(messageBytes, keyBytes);
			
			// Base64 the encrypted secret
			const encrypted_value = Buffer.from(encryptedBytes).toString('base64');
			const setResponse = await github.actions.createOrUpdateSecretForRepo(repo({
				name: secretName,
				key_id,
				encrypted_value
			}));

			if (setResponse.status !== 201 && setResponse.status !== 204) {
				log.error(`Failed to set secret ${secretName}.`, repo(), secretsResponse);
			}
		} catch (e) {
			log.error(`Failed to read secret ${secretName}.`, e, repo());
			errors++;
			if (errors >= 3) {
				log.fatal('To many errors. Aborting...');
				return;
			} 
		}
	}
};

const readSecret = async (secretPath: string, token: string, context: AppContext) => {	
	const { url: vaultUrl, namespace } = context.vaultConfig;
	const requestPath = `${vaultUrl}/v1${secretPath}`;

	return context.app.cache.wrap(requestPath, async (callback) => {
		try {
			const requestOptions: any = {
					headers: {
							'X-Vault-Token': token
					},
			};
		
			if (namespace != null) {
					requestOptions.headers["X-Vault-Namespace"] = namespace;
			}
		
			if (!secretPath.startsWith('/')) {
				secretPath = `/${secretPath}`;
			}
			const result = await got(requestPath, requestOptions);
			callback(null, result);
		} catch (e) {
			callback(e, null);
		}
	}, { ttl: 60 });
};

const getAppRoleToken = async (context: AppContext) => {
	if (!('roleId' in context.vaultConfig)) {
		throw Error('Expected role in config.');
	}

	const { roleId, secretId, namespace, url: vaultUrl } = context.vaultConfig;
	const options = {
		headers: {} as Record<string, string>,
		json: { role_id: roleId, secret_id: secretId },
		responseType: 'json' as const
	};

	if (namespace != null) {
			options.headers!["X-Vault-Namespace"] = namespace;
	}

	const result = await got.post<{ auth?: { client_token?: string }; errors?: string []}>(`${vaultUrl}/v1/auth/approle/login`, options);
	if (result && result.body && result.body.auth && result.body.auth.client_token) {
		return Ok(result.body.auth.client_token!);
	} else if (result.body.errors) {
		return Err(['Failed to login to vault.', ...result.body.errors]);
	} else {
		return Err(['Unknown error while failing to login to vault.'])
	}
}
