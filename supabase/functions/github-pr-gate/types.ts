export type Finding = {
  rule: string;
  message: string;
  path?: string;
  line?: number;
};
