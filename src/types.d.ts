module "tweetsodium" {
	export = {
		seal(message: Buffer, key: Buffer);
	}
}
