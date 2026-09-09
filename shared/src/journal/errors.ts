/** Fail-stop rejection: names the seq and reason. The caller
 * halts sync at this seq; applyEntry itself just refuses honestly. */
export class InvalidEntry extends Error {
  readonly seq: number;
  readonly reason: string;
  // no TS parameter properties: Node's strip-only mode can't run them
  constructor(seq: number, reason: string) {
    super(`invalid journal entry at seq ${seq}: ${reason}`);
    this.seq = seq;
    this.reason = reason;
  }
}

/** A builder refused to build an event applyEntry would reject
 * (builders share the verifier's predicates). */
export class BuildRefused extends Error {
  constructor(reason: string) {
    super(`refusing to build event: ${reason}`);
  }
}
