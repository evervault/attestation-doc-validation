/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export interface NodePcRs {
  hashAlgorithm?: string
  pcr0?: string
  pcr1?: string
  pcr2?: string
  pcr8?: string
}
export function attestConnection(cert: Buffer, expectedPcrs?: NodePcRs | undefined | null): boolean