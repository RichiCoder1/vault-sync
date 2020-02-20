import { Application } from "probot";

export type VaultGlobalSettings = {
	url: string;
	namespace?: string;
} & ({ token: string } | { roleId: string; secretId: string});

export const getAndVerifyGlobals = (app: Application) => {
	const env = process.env;
	if (!env['VAULT_URL']) {
		app.log.fatal('No VAULT_URL set. Exiting...');
		return null;
	}

	const settings: Record<string, string> = {
		url: env['VAULT_URL']!
	};

	if (env['VAULT_TOKEN']) {
		settings.token = env['VAULT_TOKEN'];
	} else if (env['VAULT_ROLE_ID'] && env['VAULT_SECRET_ID']) {
		settings.roleId = env['VAULT_ROLE_ID'];
		settings.secretId = env['VAULT_SECRET_ID'];
	} else {
		app.log.fatal('No authentication methods are set. Exiting...');
		return null;
	}

	if (env['VAULT_NAMESPACE']) {
		settings.namespace = env['VAULT_NAMESPACE'];
	}

	return settings as VaultGlobalSettings;
};
