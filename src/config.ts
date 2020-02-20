import { Context } from "probot";
import Joi from "@hapi/joi";

export const configFile = "vault-sync.yml";

export interface VaultSyncConfig {
	secrets: Record<string, VaultSecretConfig>;
}

export interface VaultSecretConfig {
	path: string;
	selector: string;
}

const schema = Joi.object({
	secrets: Joi.object().pattern(Joi.string(), [
		Joi.object({
			path: Joi.string().required(),
			selector: Joi.string().required(),
			namespace: Joi.string().optional(),
		}),
	]),
});

export function getConfig(context: Context) {
	const settings = context.config(configFile);
	if (!settings) {
		context.log.info(`No .github/${configFile} config found.`, context.repo());
		return null;
	}

	const { error, value } = schema.validate(settings);
	if (error) {
		context.log.fatal(
			"Failed to read repository config:",
			error,
			context.repo()
		);
		return null;
	}
	return value as VaultSyncConfig;
}
