const bcrypt = require("bcrypt");

export const hash = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, 10).then((hash: string) => hash);
};

export const compare = async (
  password: string,
  hash: string,
): Promise<boolean> => {
  return await bcrypt.compare(password, hash).then((res: boolean) => res);
};

export default { hash, compare };
